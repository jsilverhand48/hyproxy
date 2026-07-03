"""Admin CRUD API: DPoP-bound admin tokens, step-up on mutations, authz
negatives, and policy_changes audit rows."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pyotp
import pytest
from soft_webauthn import SoftWebauthnDevice
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import (
    DpopClient,
    create_user,
    credential_to_json,
    enroll_confirmed_totp,
    extract_form_fields,
    options_for_device,
    password_step,
)
from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.crypto import new_token, sha256_b64url
from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import (
    AuthEvent,
    OAuthClient,
    PolicyChange,
    Session,
    User,
    UserTotp,
)
from hyproxy.security import recovery as recovery_service
from hyproxy.security.webauthn import expected_origin

pytestmark = pytest.mark.integration

PW = "pw-admin-api"
CLIENT_ID = "admin-ui"
REDIRECT_URI = "https://admin-ui.test/callback"
HashFn = Callable[[str], str]


def issuer() -> str:
    return get_settings().issuer.rstrip("/")


@pytest.fixture
async def oauth_client(db: AsyncSession, secrets_backend: FileSecretsBackend) -> OAuthClient:
    await key_service.bootstrap_if_empty(db, secrets_backend, datetime.now(UTC))
    client = OAuthClient(client_id=CLIENT_ID, client_name="Admin UI", redirect_uris=[REDIRECT_URI])
    db.add(client)
    await db.flush()
    return client


async def login_admin_with_device(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> tuple[User, SoftWebauthnDevice]:
    user = await create_user(db, make_password_hash, tier="admin", password=PW)
    resp = await password_step(idp_client, user.email, PW)
    assert resp.status_code == 303
    flow = idp_client.cookies.get("__Host-login_flow")
    assert flow
    enroll_page = await idp_client.get(f"/auth/enroll/webauthn?flow={flow}")
    import re

    csrf = re.search(r'data-csrf="([^"]+)"', enroll_page.text).group(1)  # type: ignore[union-attr]
    device = SoftWebauthnDevice()
    opts = await idp_client.post(
        "/auth/enroll/webauthn/options", json={"flow": flow, "csrf_token": csrf}
    )
    att = device.create(options_for_device(opts.json()), expected_origin())
    await idp_client.post(
        "/auth/enroll/webauthn/verify",
        json={
            "flow": flow,
            "csrf_token": csrf,
            "credential": credential_to_json(att),
            "friendly_name": "primary",
        },
    )
    opts = await idp_client.post("/auth/webauthn/options", json={"flow": flow, "csrf_token": csrf})
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    done = await idp_client.post(
        "/auth/webauthn/verify",
        json={"flow": flow, "csrf_token": csrf, "credential": credential_to_json(assertion)},
    )
    assert done.status_code == 200, done.text
    return user, device


async def obtain_token(idp_client: httpx.AsyncClient, dpop: DpopClient) -> str:
    verifier = new_token(48)
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": new_token(16),
        "nonce": new_token(16),
        "code_challenge": sha256_b64url(verifier),
        "code_challenge_method": "S256",
    }
    resp = await idp_client.get("/oidc/authorize", params=params)
    assert resp.status_code == 302, resp.text
    code = parse_qs(urlsplit(resp.headers["location"]).query)["code"][0]
    resp = await idp_client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        headers={"DPoP": dpop.proof("POST", f"{issuer()}/oidc/token")},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])


async def stepup(idp_client: httpx.AsyncClient, device: SoftWebauthnDevice) -> None:
    opts = await idp_client.post("/auth/stepup/options")
    assert opts.status_code == 200, opts.text
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    verify = await idp_client.post(
        "/auth/stepup/verify", json={"credential": credential_to_json(assertion)}
    )
    assert verify.status_code == 200


async def admin_call(
    admin_client: httpx.AsyncClient,
    dpop: DpopClient,
    token: str,
    method: str,
    path: str,
    json_body: Any = None,
) -> httpx.Response:
    url = f"https://admin.test{path}"
    proof = dpop.proof(method, url, access_token=token)
    return await admin_client.request(
        method,
        path,
        json=json_body,
        headers={"Authorization": f"DPoP {token}", "DPoP": proof},
    )


@pytest.fixture
async def admin_ctx(
    idp_client: httpx.AsyncClient,
    admin_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    oauth_client: OAuthClient,
) -> dict[str, Any]:
    user, device = await login_admin_with_device(idp_client, db, make_password_hash)
    dpop = DpopClient()
    token = await obtain_token(idp_client, dpop)
    await stepup(idp_client, device)
    return {"user": user, "device": device, "dpop": dpop, "token": token}


async def test_crud_with_stepup_and_change_log(
    admin_ctx: dict[str, Any], admin_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    dpop, token = admin_ctx["dpop"], admin_ctx["token"]

    role = await admin_call(
        admin_client, dpop, token, "POST", "/api/v1/roles", {"name": "media-users"}
    )
    assert role.status_code == 201, role.text
    role_id = role.json()["id"]

    resource = await admin_call(
        admin_client,
        dpop,
        token,
        "POST",
        "/api/v1/resources",
        {"name": "plex", "protocol": "https", "host": "10.0.0.5", "ports": [32400]},
    )
    assert resource.status_code == 201, resource.text
    resource_id = resource.json()["id"]

    policy = await admin_call(
        admin_client,
        dpop,
        token,
        "POST",
        "/api/v1/policies",
        {"role_id": role_id, "resource_id": resource_id, "action": "allow"},
    )
    assert policy.status_code == 201, policy.text
    policy_id = policy.json()["id"]

    patched = await admin_call(
        admin_client, dpop, token, "PATCH", f"/api/v1/policies/{policy_id}", {"enabled": False}
    )
    assert patched.status_code == 200 and patched.json()["enabled"] is False

    listing = await admin_call(admin_client, dpop, token, "GET", "/api/v1/policies")
    assert listing.status_code == 200 and len(listing.json()) == 1

    changes = (await db.scalars(select(PolicyChange))).all()
    kinds = {(c.entity_type, c.action) for c in changes}
    assert {
        ("role", "create"),
        ("resource", "create"),
        ("policy", "create"),
        ("policy", "update"),
    } <= kinds
    assert all(c.actor_id == admin_ctx["user"].id for c in changes)


async def test_resource_public_host_set_normalized_and_unique(
    admin_ctx: dict[str, Any], admin_client: httpx.AsyncClient
) -> None:
    dpop, token = admin_ctx["dpop"], admin_ctx["token"]

    # Create with a public_host; it is normalized (lowercased, trailing dot stripped).
    created = await admin_call(
        admin_client,
        dpop,
        token,
        "POST",
        "/api/v1/resources",
        {
            "name": "plex",
            "protocol": "https",
            "public_host": "Plex.Test.",
            "host": "10.0.0.5",
            "ports": [32400],
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["public_host"] == "plex.test"
    rid = created.json()["id"]

    # A second resource cannot claim the same routing host.
    dup = await admin_call(
        admin_client,
        dpop,
        token,
        "POST",
        "/api/v1/resources",
        {
            "name": "plex2",
            "protocol": "https",
            "public_host": "plex.test",
            "host": "10.0.0.6",
            "ports": [1],
        },
    )
    assert dup.status_code == 409, dup.text

    # Malformed hosts are rejected by the schema (422), matching the edge's rules.
    bad = await admin_call(
        admin_client,
        dpop,
        token,
        "POST",
        "/api/v1/resources",
        {
            "name": "bad",
            "protocol": "https",
            "public_host": "no_underscores",
            "host": "10.0.0.7",
            "ports": [1],
        },
    )
    assert bad.status_code == 422, bad.text

    # Patching the route to null clears it; re-adding it elsewhere then works.
    cleared = await admin_call(
        admin_client, dpop, token, "PATCH", f"/api/v1/resources/{rid}", {"public_host": None}
    )
    assert cleared.status_code == 200 and cleared.json()["public_host"] is None


async def test_reads_ok_but_mutations_need_stepup(
    idp_client: httpx.AsyncClient,
    admin_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    oauth_client: OAuthClient,
) -> None:
    _user, _device = await login_admin_with_device(idp_client, db, make_password_hash)
    dpop = DpopClient()
    token = await obtain_token(idp_client, dpop)  # no step-up performed

    reads = await admin_call(admin_client, dpop, token, "GET", "/api/v1/users")
    assert reads.status_code == 200

    write = await admin_call(admin_client, dpop, token, "POST", "/api/v1/roles", {"name": "nope"})
    assert write.status_code == 403
    assert write.json()["detail"] == "stepup_required"


async def test_stale_stepup_rejected(
    admin_ctx: dict[str, Any], admin_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    session = await db.scalar(select(Session).where(Session.user_id == admin_ctx["user"].id))
    assert session is not None
    session.step_up_verified_at = datetime.now(UTC) - timedelta(minutes=10)
    await db.flush()
    resp = await admin_call(
        admin_client,
        admin_ctx["dpop"],
        admin_ctx["token"],
        "POST",
        "/api/v1/roles",
        {"name": "stale"},
    )
    assert resp.status_code == 403 and resp.json()["detail"] == "stepup_required"


async def test_standard_tier_token_rejected(
    idp_client: httpx.AsyncClient,
    admin_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    oauth_client: OAuthClient,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)
    resp = await password_step(idp_client, user.email, PW)
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    await idp_client.post("/auth/totp", data={**fields, "code": pyotp.TOTP(secret).now()})

    dpop = DpopClient()
    token = await obtain_token(idp_client, dpop)
    resp = await admin_call(admin_client, dpop, token, "GET", "/api/v1/users")
    assert resp.status_code == 403


async def test_no_token_rejected_with_dpop_challenge(
    admin_client: httpx.AsyncClient,
) -> None:
    resp = await admin_client.get("/api/v1/users")
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"].startswith("DPoP")


async def test_promote_to_admin_requires_two_passkeys(
    admin_ctx: dict[str, Any],
    admin_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
) -> None:
    target = await create_user(db, make_password_hash, tier="standard", password=PW)
    resp = await admin_call(
        admin_client,
        admin_ctx["dpop"],
        admin_ctx["token"],
        "PATCH",
        f"/api/v1/users/{target.id}",
        {"auth_tier": "admin"},
    )
    assert resp.status_code == 409


async def test_admin_totp_reset_flow(
    admin_ctx: dict[str, Any],
    admin_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    target = await create_user(db, make_password_hash, tier="standard", password=PW)
    await enroll_confirmed_totp(db, secrets_backend, target)
    await recovery_service.issue_batch(db, target.id)

    resp = await admin_call(
        admin_client,
        admin_ctx["dpop"],
        admin_ctx["token"],
        "POST",
        f"/api/v1/users/{target.id}/reset-totp",
    )
    assert resp.status_code == 204, resp.text

    assert await db.get(UserTotp, target.id) is None
    events = [
        e.event_type
        for e in (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == target.id))).all()
    ]
    assert "admin.totp_reset" in events
    changes = (
        await db.scalars(select(PolicyChange).where(PolicyChange.entity_type == "totp_reset"))
    ).all()
    assert len(changes) == 1


async def test_revoke_user_sessions_via_admin_api(
    admin_ctx: dict[str, Any],
    idp_client: httpx.AsyncClient,
    admin_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
) -> None:
    admin_user: User = admin_ctx["user"]
    resp = await admin_call(
        admin_client,
        admin_ctx["dpop"],
        admin_ctx["token"],
        "POST",
        f"/api/v1/users/{admin_user.id}/sessions/revoke",
    )
    assert resp.status_code == 204

    session = await db.scalar(select(Session).where(Session.user_id == admin_user.id))
    assert session is not None and session.revoked_at is not None

    # Immediate revocation: the still-valid JWT no longer works anywhere.
    after = await admin_call(
        admin_client, admin_ctx["dpop"], admin_ctx["token"], "GET", "/api/v1/users"
    )
    assert after.status_code == 401


async def test_create_and_delete_user(
    admin_ctx: dict[str, Any], admin_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    created = await admin_call(
        admin_client,
        admin_ctx["dpop"],
        admin_ctx["token"],
        "POST",
        "/api/v1/users",
        {
            "email": f"{uuid.uuid4()}@example.com",
            "display_name": "New User",
            "auth_tier": "standard",
            "temp_password": "a-long-temp-password",
        },
    )
    assert created.status_code == 201, created.text
    new_id = created.json()["id"]

    deleted = await admin_call(
        admin_client, admin_ctx["dpop"], admin_ctx["token"], "DELETE", f"/api/v1/users/{new_id}"
    )
    assert deleted.status_code == 204
    assert await db.get(User, uuid.UUID(new_id)) is None

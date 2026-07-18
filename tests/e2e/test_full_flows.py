"""Flagship end-to-end journeys through the reference RP (tests/rp/app.py).

Standard user: authorize -> login (password + TOTP) -> code -> DPoP token
exchange -> userinfo -> silent refresh -> reuse-detection kill -> re-login ->
revocation -> re-auth required after simulated IP change.

Admin: password + WebAuthn (soft authenticator) -> tokens -> step-up ->
admin API mutation -> session revocation via the admin API kills the token.
"""

import re
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
import pyotp
import pytest
from soft_webauthn import SoftWebauthnDevice
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import (
    create_user,
    credential_to_json,
    enroll_confirmed_totp,
    extract_form_fields,
    options_for_device,
)
from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import OAuthClient, Session
from hyproxy.security.webauthn import expected_origin
from rp.app import CLIENT_ID, REDIRECT_URI, RpSimulator

pytestmark = pytest.mark.e2e

PW = "pw-e2e-flows"
HashFn = Callable[[str], str]


@pytest.fixture
async def rp(
    idp_client: httpx.AsyncClient, db: AsyncSession, secrets_backend: FileSecretsBackend
) -> RpSimulator:
    await key_service.bootstrap_if_empty(db, secrets_backend, datetime.now(UTC))
    db.add(OAuthClient(client_id=CLIENT_ID, client_name="E2E RP", redirect_uris=[REDIRECT_URI]))
    await db.flush()
    return RpSimulator(idp_client, get_settings().issuer)


async def complete_totp_login(
    idp: httpx.AsyncClient, login_redirect: str, email: str, secret: str
) -> str:
    """Drives the login UI from the /auth/login redirect; returns the final
    authorize redirect (RP callback URL)."""
    page = await idp.get(login_redirect)
    fields = extract_form_fields(page.text)
    resp = await idp.post("/auth/login", data={**fields, "email": email, "password": PW})
    assert resp.status_code == 303, resp.text
    page = await idp.get(resp.headers["location"])  # /auth/totp
    fields = extract_form_fields(page.text)
    resp = await idp.post("/auth/totp", data={**fields, "code": pyotp.TOTP(secret).now()})
    assert resp.status_code == 303, resp.text  # back to /oidc/authorize
    resp = await idp.get(resp.headers["location"])
    assert resp.status_code == 302, resp.text  # code redirect to the RP
    return resp.headers["location"]


async def test_standard_user_full_journey(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp: RpSimulator,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)

    # 1. RP sends the browser to authorize; unauthenticated -> login flow.
    authorize_url, rp_session = rp.start_login()
    resp = await idp_client.get(authorize_url)
    assert resp.status_code == 303 and resp.headers["location"].startswith("/auth/login")

    # 2. Password + TOTP, then authorize resumes and redirects with a code.
    callback = await complete_totp_login(idp_client, resp.headers["location"], user.email, secret)
    assert callback.startswith(REDIRECT_URI)
    code = rp.parse_callback(callback, rp_session)

    # 3. DPoP-bound token exchange, ID token nonce round-trip.
    resp = await rp.exchange_code(code, rp_session)
    assert resp.status_code == 200, resp.text
    id_claims = _decode_unverified(rp_session.id_token)
    assert id_claims["nonce"] == rp_session.nonce
    assert id_claims["acr"] == "tier:standard"

    # 4. userinfo with proof + ath.
    ui = await rp.userinfo(rp_session)
    assert ui.status_code == 200 and ui.json()["sub"] == user.external_id

    # 5. Silent refresh rotates the token.
    old_refresh = rp_session.refresh_token
    assert (await rp.refresh(rp_session)).status_code == 200
    assert rp_session.refresh_token != old_refresh

    # 6. A replayed (stolen) old refresh token kills the whole session family.
    stolen = await rp.idp.post(
        "/oidc/token",
        data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": old_refresh,
        },
        headers={"DPoP": rp.dpop.proof("POST", f"{rp.issuer}/oidc/token")},
    )
    assert stolen.status_code == 400
    assert (await rp.refresh(rp_session)).status_code == 400  # family dead
    assert (await rp.userinfo(rp_session)).status_code == 401  # session dead

    # 7. Full re-login required; a fresh journey works again.
    authorize_url, rp_session = rp.start_login()
    resp = await idp_client.get(authorize_url)
    callback = await complete_totp_login(idp_client, resp.headers["location"], user.email, secret)
    assert (
        await rp.exchange_code(rp.parse_callback(callback, rp_session), rp_session)
    ).status_code == 200

    # 8. Logout via revocation is immediate.
    assert (await rp.logout(rp_session)).status_code == 200
    assert (await rp.userinfo(rp_session)).status_code == 401

    # 9. Third login, then the user's public IP "changes": session goes stale.
    authorize_url, rp_session = rp.start_login()
    resp = await idp_client.get(authorize_url)
    callback = await complete_totp_login(idp_client, resp.headers["location"], user.email, secret)
    assert (
        await rp.exchange_code(rp.parse_callback(callback, rp_session), rp_session)
    ).status_code == 200
    live = await db.scalar(
        select(Session).where(Session.user_id == user.id, Session.revoked_at.is_(None))
    )
    assert live is not None
    live.source_ip = "203.0.113.200"
    await db.flush()
    assert (await rp.userinfo(rp_session)).status_code == 401
    assert (await rp.refresh(rp_session)).status_code == 400
    await db.refresh(live)
    assert live.stale is True


async def test_admin_full_journey_with_stepup(
    idp_client: httpx.AsyncClient,
    admin_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp: RpSimulator,
) -> None:
    admin = await create_user(db, make_password_hash, tier="admin", password=PW)

    # 1. Authorize -> login flow -> password step routes to WebAuthn only.
    authorize_url, rp_session = rp.start_login()
    resp = await idp_client.get(authorize_url)
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    resp = await idp_client.post(
        "/auth/login", data={**fields, "email": admin.email, "password": PW}
    )
    assert resp.headers["location"].startswith("/auth/webauthn")
    flow = idp_client.cookies.get("__Host-login_flow")
    assert flow

    # 2. Bootstrap enrollment (primary + break-glass), then assert.
    enroll_page = await idp_client.get(f"/auth/enroll/webauthn?flow={flow}")
    csrf = re.search(r'data-csrf="([^"]+)"', enroll_page.text).group(1)  # type: ignore[union-attr]
    device = SoftWebauthnDevice()
    for name, bg in (("primary", False), ("safe-key", True)):
        dev = device if not bg else SoftWebauthnDevice()
        opts = await idp_client.post(
            "/auth/enroll/webauthn/options", json={"flow": flow, "csrf_token": csrf}
        )
        att = dev.create(options_for_device(opts.json()), expected_origin())
        r = await idp_client.post(
            "/auth/enroll/webauthn/verify",
            json={
                "flow": flow,
                "csrf_token": csrf,
                "credential": credential_to_json(att),
                "friendly_name": name,
                "break_glass": bg,
            },
        )
        assert r.status_code == 200, r.text

    opts = await idp_client.post("/auth/webauthn/options", json={"flow": flow, "csrf_token": csrf})
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    done = await idp_client.post(
        "/auth/webauthn/verify",
        json={"flow": flow, "csrf_token": csrf, "credential": credential_to_json(assertion)},
    )
    assert done.status_code == 200, done.text
    # The webauthn JSON path resumes the parked authorize request.
    callback_url = done.json()["redirect"]
    resp = await idp_client.get(callback_url)
    assert resp.status_code == 302
    code = rp.parse_callback(resp.headers["location"], rp_session)
    assert (await rp.exchange_code(code, rp_session)).status_code == 200
    assert _decode_unverified(rp_session.id_token)["acr"] == "tier:admin"

    # 3. Admin API mutation requires step-up; perform it and create a role.
    def admin_headers(method: str, path: str) -> dict[str, str]:
        url = f"https://admin.test{path}"
        return {
            "Authorization": f"DPoP {rp_session.access_token}",
            "DPoP": rp.dpop.proof(method, url, access_token=rp_session.access_token),
        }

    denied = await admin_client.post(
        "/api/v1/roles", json={"name": "e2e-role"}, headers=admin_headers("POST", "/api/v1/roles")
    )
    assert denied.status_code == 403 and denied.json()["detail"] == "stepup_required"

    opts = await idp_client.post("/auth/stepup/options")
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    verified = await idp_client.post(
        "/auth/stepup/verify", json={"credential": credential_to_json(assertion)}
    )
    assert verified.status_code == 200

    created = await admin_client.post(
        "/api/v1/roles", json={"name": "e2e-role"}, headers=admin_headers("POST", "/api/v1/roles")
    )
    assert created.status_code == 201, created.text

    # 4. Revoking the admin's sessions through the admin API kills the token.
    path = f"/api/v1/users/{admin.id}/sessions/revoke"
    revoked = await admin_client.post(path, headers=admin_headers("POST", path))
    assert revoked.status_code == 204
    after = await admin_client.get("/api/v1/users", headers=admin_headers("GET", "/api/v1/users"))
    assert after.status_code == 401
    assert (await rp.userinfo(rp_session)).status_code == 401


def _decode_unverified(token: str) -> dict[str, object]:
    import base64
    import json

    payload = token.split(".")[1]
    result = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert isinstance(result, dict)
    return result

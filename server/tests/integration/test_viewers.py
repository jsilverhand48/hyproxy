"""Read-only viewer endpoints: audit_log, auth_events, policy_changes.

Covers admin-tier gating (no step-up needed for reads), filtering, and keyset
pagination. Rows are seeded directly on the shared test session, which the admin
app reads through the same rolled-back transaction.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import DpopClient, create_user, password_step
from hyproxy.db.models import AuditLog, AuthEvent, PolicyChange, User

pytestmark = pytest.mark.integration


def _ctx(admin_session: dict[str, Any]) -> tuple[DpopClient, str, User]:
    return admin_session["dpop"], admin_session["token"], admin_session["user"]


async def test_access_audit_filter_and_shape(
    admin_session: dict[str, Any], admin_get: Any, db: AsyncSession
) -> None:
    dpop, token, _ = _ctx(admin_session)
    keep = None
    for i in range(3):
        row = AuditLog(
            decision="allow" if i else "deny",
            reason="policy",
            source_ip="10.0.0.5",
            port=443,
        )
        db.add(row)
        if i == 0:
            keep = row
    await db.flush()

    resp = await admin_get(dpop, token, "/api/v1/audit/access?decision=deny")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert {r["decision"] for r in body["items"]} == {"deny"}
    assert body["items"][0]["id"] == keep.id  # type: ignore[union-attr]
    assert body["items"][0]["source_ip"] == "10.0.0.5"


async def test_auth_events_success_filter(
    admin_session: dict[str, Any], admin_get: Any, db: AsyncSession
) -> None:
    dpop, token, _ = _ctx(admin_session)
    db.add(AuthEvent(event_type="login.password", source_ip="10.0.0.9", success=False))
    db.add(AuthEvent(event_type="login.webauthn", source_ip="10.0.0.9", success=True))
    await db.flush()

    resp = await admin_get(
        dpop, token, "/api/v1/audit/auth?event_type=login.password&success=false"
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert items and all(
        i["event_type"] == "login.password" and i["success"] is False for i in items
    )


async def test_policy_changes_join_actor_email(
    admin_session: dict[str, Any], admin_get: Any, db: AsyncSession
) -> None:
    dpop, token, admin = _ctx(admin_session)
    db.add(
        PolicyChange(
            actor_id=admin.id,
            entity_type="role",
            entity_id=None,
            action="create",
            change_json={"before": None, "after": {"name": "x"}},
        )
    )
    await db.flush()

    resp = await admin_get(dpop, token, "/api/v1/policy-changes?entity_type=role")
    assert resp.status_code == 200, resp.text
    item = resp.json()["items"][0]
    assert item["actor_email"] == admin.email
    assert item["change_json"]["after"]["name"] == "x"


async def test_keyset_pagination(
    admin_session: dict[str, Any], admin_get: Any, db: AsyncSession
) -> None:
    dpop, token, _ = _ctx(admin_session)
    for _ in range(5):
        db.add(AuditLog(decision="allow", source_ip="10.0.0.1"))
    await db.flush()

    first = (await admin_get(dpop, token, "/api/v1/audit/access?decision=allow&limit=2")).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"] is not None

    cur = first["next_cursor"]
    second = (
        await admin_get(dpop, token, f"/api/v1/audit/access?decision=allow&limit=2&cursor={cur}")
    ).json()
    # Descending ids: the second page holds strictly older rows.
    assert max(i["id"] for i in second["items"]) < min(i["id"] for i in first["items"])


async def test_since_until_window(
    admin_session: dict[str, Any], admin_get: Any, db: AsyncSession
) -> None:
    dpop, token, _ = _ctx(admin_session)
    old = AuditLog(decision="allow", source_ip="10.0.0.1", ts=datetime.now(UTC) - timedelta(days=2))
    recent = AuditLog(decision="allow", source_ip="10.0.0.1", ts=datetime.now(UTC))
    db.add_all([old, recent])
    await db.flush()

    from urllib.parse import quote

    since = quote((datetime.now(UTC) - timedelta(hours=1)).isoformat(), safe="")
    resp = await admin_get(dpop, token, f"/api/v1/audit/access?decision=allow&since={since}")
    ids = {i["id"] for i in resp.json()["items"]}
    assert recent.id in ids and old.id not in ids


async def test_viewers_reject_standard_tier(
    admin_get: Any,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: Any,
    secrets_backend: Any,
    admin_ui_client: Any,
) -> None:
    from urllib.parse import parse_qs, urlsplit

    import pyotp

    from helpers import enroll_confirmed_totp, extract_form_fields
    from hyproxy.config import get_settings
    from hyproxy.core.crypto import new_token, sha256_b64url

    user = await create_user(db, make_password_hash, tier="standard", password="pw-standard-x")
    secret = await enroll_confirmed_totp(db, secrets_backend, user)
    resp = await password_step(idp_client, user.email, "pw-standard-x")
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    await idp_client.post("/auth/totp", data={**fields, "code": pyotp.TOTP(secret).now()})

    dpop = DpopClient()
    verifier = new_token(48)
    params = {
        "client_id": "admin-ui",
        "redirect_uri": "https://admin-ui.test/callback",
        "response_type": "code",
        "scope": "openid profile email",
        "state": new_token(16),
        "nonce": new_token(16),
        "code_challenge": sha256_b64url(verifier),
        "code_challenge_method": "S256",
    }
    a = await idp_client.get("/oidc/authorize", params=params)
    code = parse_qs(urlsplit(a.headers["location"]).query)["code"][0]
    tok = await idp_client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "admin-ui",
            "code": code,
            "redirect_uri": "https://admin-ui.test/callback",
            "code_verifier": verifier,
        },
        headers={"DPoP": dpop.proof("POST", f"{get_settings().issuer.rstrip('/')}/oidc/token")},
    )
    token = tok.json()["access_token"]

    resp = await admin_get(dpop, token, "/api/v1/audit/access")
    assert resp.status_code == 403


async def test_viewers_require_token(admin_client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/audit/access", "/api/v1/audit/auth", "/api/v1/policy-changes"):
        resp = await admin_client.get(path)
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"].startswith("DPoP")

"""Shared machinery for admin-API integration tests: log an admin in through
the real WebAuthn flow, obtain a DPoP-bound access token against the `admin-ui`
client, perform step-up, and issue authenticated admin calls."""

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from soft_webauthn import SoftWebauthnDevice
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import (
    DpopClient,
    create_user,
    credential_to_json,
    options_for_device,
    password_step,
)
from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.crypto import new_token, sha256_b64url
from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import OAuthClient, User
from hyproxy.security.webauthn import expected_origin

ADMIN_PW = "pw-admin-viewer"
ADMIN_UI_CLIENT = "admin-ui"
ADMIN_UI_REDIRECT = "https://admin-ui.test/callback"


def _issuer() -> str:
    return get_settings().issuer.rstrip("/")


@pytest.fixture
async def admin_ui_client(db: AsyncSession, secrets_backend: FileSecretsBackend) -> OAuthClient:
    await key_service.bootstrap_if_empty(db, secrets_backend, datetime.now(UTC))
    client = OAuthClient(
        client_id=ADMIN_UI_CLIENT,
        client_name="Admin UI",
        redirect_uris=[ADMIN_UI_REDIRECT],
    )
    db.add(client)
    await db.flush()
    return client


async def _login_admin(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: Any
) -> tuple[User, SoftWebauthnDevice]:
    user = await create_user(db, make_password_hash, tier="admin", password=ADMIN_PW)
    resp = await password_step(idp_client, user.email, ADMIN_PW)
    assert resp.status_code == 303
    flow = idp_client.cookies.get("__Host-login_flow")
    assert flow
    enroll_page = await idp_client.get(f"/auth/enroll/webauthn?flow={flow}")
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


async def _obtain_token(idp_client: httpx.AsyncClient, dpop: DpopClient) -> str:
    verifier = new_token(48)
    params = {
        "client_id": ADMIN_UI_CLIENT,
        "redirect_uri": ADMIN_UI_REDIRECT,
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
            "client_id": ADMIN_UI_CLIENT,
            "code": code,
            "redirect_uri": ADMIN_UI_REDIRECT,
            "code_verifier": verifier,
        },
        headers={"DPoP": dpop.proof("POST", f"{_issuer()}/oidc/token")},
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])


async def _stepup(idp_client: httpx.AsyncClient, device: SoftWebauthnDevice) -> None:
    opts = await idp_client.post("/auth/stepup/options")
    assert opts.status_code == 200, opts.text
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    verify = await idp_client.post(
        "/auth/stepup/verify", json={"credential": credential_to_json(assertion)}
    )
    assert verify.status_code == 200


@pytest.fixture
async def admin_session(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: Any,
    admin_ui_client: OAuthClient,
) -> dict[str, Any]:
    """An authenticated, stepped-up admin: user, DPoP client, access token."""
    user, device = await _login_admin(idp_client, db, make_password_hash)
    dpop = DpopClient()
    token = await _obtain_token(idp_client, dpop)
    await _stepup(idp_client, device)
    return {"user": user, "device": device, "dpop": dpop, "token": token}


@pytest.fixture
def admin_get(admin_client: httpx.AsyncClient) -> Any:
    """Callable `(dpop, token, path) -> Response` issuing a DPoP-bound GET."""

    async def _get(dpop: DpopClient, token: str, path: str) -> httpx.Response:
        url = f"https://admin.test{path}"
        proof = dpop.proof("GET", url, access_token=token)
        return await admin_client.get(
            path, headers={"Authorization": f"DPoP {token}", "DPoP": proof}
        )

    return _get

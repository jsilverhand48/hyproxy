"""The GET /auth/stepup page: a top-level navigation that runs a fresh WebAuthn
assertion and returns only to the validated admin-UI origin."""

from typing import Any

import httpx
import pytest

from hyproxy.config import get_settings

pytestmark = pytest.mark.integration


async def test_stepup_page_gated_and_origin_validated(
    admin_session: dict[str, Any],  # logs an admin in; leaves the session cookie on idp_client
    idp_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "admin_ui_origin", "https://admin-ui.test")

    bad = await idp_client.get("/auth/stepup", params={"return_to": "https://evil.test/"})
    assert bad.status_code == 400

    missing = await idp_client.get("/auth/stepup")
    assert missing.status_code == 400

    ok = await idp_client.get("/auth/stepup", params={"return_to": "https://admin-ui.test/users"})
    assert ok.status_code == 200
    assert "/static/js/stepup.js" in ok.text
    assert 'data-return-to="https://admin-ui.test/users"' in ok.text


async def test_stepup_page_requires_admin_session(
    admin_ui_client: Any,
    idp_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "admin_ui_origin", "https://admin-ui.test")
    # No session cookie: a valid origin still cannot reach the page.
    resp = await idp_client.get("/auth/stepup", params={"return_to": "https://admin-ui.test/"})
    assert resp.status_code == 401

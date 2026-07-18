"""The admin app serves the built SPA same-origin with the API, under a strict
CSP whose connect-src admits the IdP origin (for the token exchange)."""

import httpx
import pytest

pytestmark = pytest.mark.integration


async def test_serves_spa_index_with_strict_csp(admin_client: httpx.AsyncClient) -> None:
    resp = await admin_client.get("/")
    if resp.status_code == 404:
        pytest.skip("ui/dist not built; SPA serving is optional")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert 'id="root"' in resp.text

    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp
    assert "connect-src 'self' https://idp.localhost:8300" in csp


async def test_client_route_falls_back_to_index(admin_client: httpx.AsyncClient) -> None:
    resp = await admin_client.get("/policies")
    if resp.status_code == 404:
        pytest.skip("ui/dist not built")
    assert resp.status_code == 200
    assert 'id="root"' in resp.text


async def test_unknown_api_path_is_not_shadowed_by_spa(admin_client: httpx.AsyncClient) -> None:
    # An unknown /api path must 404 as an API, never return SPA HTML.
    resp = await admin_client.get("/api/v1/does-not-exist")
    assert resp.status_code in (401, 404)
    assert "text/html" not in resp.headers.get("content-type", "")

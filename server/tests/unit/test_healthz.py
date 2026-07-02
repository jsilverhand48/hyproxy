import httpx

from hyproxy.admin.app import create_app as create_admin_app
from hyproxy.idp.app import create_app as create_idp_app


async def test_idp_healthz() -> None:
    transport = httpx.ASGITransport(app=create_idp_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "idp"}


async def test_admin_healthz() -> None:
    transport = httpx.ASGITransport(app=create_admin_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "admin"}

"""GET /authz/routes: the DB-derived route table the data plane hot-loads.

Only enabled resources with a public_host are emitted; http/https become
reverse-proxy backends, vnc/rdp/ssh become guac-tunnel routes, tcp is skipped.
"""

import uuid

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import Resource


async def _add(db: AsyncSession, **kw: object) -> Resource:
    row = Resource(name=f"res-{uuid.uuid4()}", **kw)
    db.add(row)
    await db.flush()
    return row


async def test_routes_derives_http_guac_and_skips_the_rest(
    authz_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    await _add(db, protocol="https", public_host="plex.test", host="10.0.0.5", ports=[32400])
    await _add(db, protocol="http", public_host="photos.test", host="10.0.0.6", ports=[80, 8080])
    await _add(db, protocol="rdp", public_host="desktop.test", host="10.0.0.7", ports=[3389])
    # Excluded: disabled, no public_host, and a non-L7 tcp resource.
    await _add(
        db, protocol="http", public_host="off.test", host="10.0.0.8", ports=[80], enabled=False
    )
    await _add(db, protocol="http", public_host=None, host="10.0.0.9", ports=[80])
    await _add(db, protocol="tcp", public_host="raw.test", host="10.0.0.10", ports=[5432])

    resp = await authz_client.get("/authz/routes")
    assert resp.status_code == 200, resp.text
    routes = resp.json()["routes"]

    assert set(routes) == {"plex.test", "photos.test", "desktop.test"}
    assert routes["plex.test"] == {
        "backend": "https://10.0.0.5:32400",
        "backend_port": 32400,
        "guac_tunnel": False,
    }
    # First port is the backend port.
    assert routes["photos.test"]["backend"] == "http://10.0.0.6:80"
    # Guac resources carry no backend; the data plane supplies the tunnel origin.
    assert routes["desktop.test"] == {"backend": None, "backend_port": 0, "guac_tunnel": True}


async def test_routes_empty_when_no_resources(
    authz_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    resp = await authz_client.get("/authz/routes")
    assert resp.status_code == 200
    assert resp.json() == {"routes": {}}

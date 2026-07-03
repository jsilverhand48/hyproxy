"""GET /authz/routes: the data plane's route table, derived from resources.

Internal-only, like /authz/check (loopback / data-plane network; never proxied
to clients). The Go data plane polls this and hot-swaps its routing table, so an
admin adding a resource in the UI makes the route live without a restart.

Backends are chosen ONLY from server-side resource rows, never from client
input, preserving the data plane's SSRF invariant. Only enabled resources with a
routing host are emitted:

  - http/https -> a reverse-proxy route to {protocol}://{host}:{ports[0]}
  - vnc/rdp/ssh -> a Guacamole tunnel route (the data plane supplies the tunnel
    backend from its own config; the connection's real host stays sealed)
  - tcp -> skipped (not an L7 backend today; awaits the raw-L4 listener seam)
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.engine import get_db
from hyproxy.db.models import Resource

router = APIRouter()

DbDep = Annotated[AsyncSession, Depends(get_db)]

_GUAC_PROTOCOLS = {"vnc", "rdp", "ssh"}
_HTTP_PROTOCOLS = {"http", "https"}


class RouteOut(BaseModel):
    # Absolute http(s) backend origin (no path); omitted for guac tunnels.
    backend: str | None = None
    # Backend port reported to the policy engine (0 when derived by the data plane).
    backend_port: int = 0
    # True for Guacamole tunnel routes; the data plane routes these to its
    # configured tunnel backend instead of dialing the resource host directly.
    guac_tunnel: bool = False


class RoutesResponse(BaseModel):
    routes: dict[str, RouteOut]


@router.get("/authz/routes")
async def routes(db: DbDep) -> RoutesResponse:
    rows = await db.scalars(
        select(Resource).where(
            Resource.enabled.is_(True), Resource.public_host.is_not(None)
        )
    )
    table: dict[str, RouteOut] = {}
    for r in rows:
        host = (r.public_host or "").strip().lower().rstrip(".")
        if not host:
            continue
        if r.protocol in _HTTP_PROTOCOLS:
            if not r.ports:
                continue
            port = r.ports[0]
            table[host] = RouteOut(
                backend=f"{r.protocol}://{r.host}:{port}", backend_port=port
            )
        elif r.protocol in _GUAC_PROTOCOLS:
            table[host] = RouteOut(guac_tunnel=True)
        # tcp and anything else: not an L7 route yet, skip.
    return RoutesResponse(routes=table)

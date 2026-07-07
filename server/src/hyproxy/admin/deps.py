"""Admin API auth: DPoP-bound access token + admin tier, step-up for mutations.

The admin API is a resource server for the IdP's tokens and runs the same
check_request contract (JWT + DPoP + session liveness + IP binding). The
management endpoints (require_admin) are never internet-facing: LAN/WireGuard
only (docs/admin-access.md). The /api/v1/portal endpoints (require_user /
require_portal_admin) are also served on the internet-facing portal host.
"""

import ipaddress
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core.netutil import resolve_client_ip
from hyproxy.db.engine import get_db
from hyproxy.idp import sessions

DbDep = Annotated[AsyncSession, Depends(get_db)]


def client_ip(request: Request) -> str:
    return resolve_client_ip(request)


@lru_cache(maxsize=4)
def _lan_networks(cidrs: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(c.strip()) for c in cidrs.split(",") if c.strip())


def require_lan_client(request: Request) -> None:
    """Reject admin API calls from outside admin_lan_cidrs (403).

    Defense in depth behind the data plane's lan_only edge block, so a
    re-rendered proxy config cannot silently re-expose the console. The client
    IP comes from the data plane's sanitized X-Forwarded-For (uvicorn
    --proxy-headers); only the data plane can reach the loopback-published
    port. Empty setting disables the check (dev).
    """
    cidrs = get_settings().admin_lan_cidrs
    if not cidrs:
        return
    try:
        addr = ipaddress.ip_address(client_ip(request))
    except ValueError:
        addr = None
    if addr is None or not any(addr in net for net in _lan_networks(cidrs)):
        raise HTTPException(
            status_code=403, detail="admin console is restricted to the local network"
        )


def _expected_htu(request: Request) -> str:
    """DPoP htu for admin API calls, pinned to a configured public origin.

    The SPA signs the proof over its own origin (window.location.origin +
    /api/v1/...). Behind the data-plane proxy the Host header is rewritten to
    the internal backend vhost, and uvicorn's --proxy-headers honors
    X-Forwarded-Proto but not X-Forwarded-Host, so str(request.url) carries the
    wrong host and every proof would fail htu comparison. Rebuild htu from the
    configured origins; the path is the one part of the request URL that is
    authoritative. The app is served on up to two public hosts (admin console
    and standard-user portal), so pick the origin whose host matches the data
    plane's X-Forwarded-Host. Allowlist only: the header selects among the
    configured origins and is never itself echoed into the htu. Fall back to
    the raw URL when no origin is configured (dev / no proxy), where they
    already agree.
    """
    settings = get_settings()
    origins = [o for o in (settings.admin_ui_origin, settings.portal_origin) if o]
    if not origins:
        return str(request.url)
    fwd_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip().lower()
    origin = origins[0]
    if fwd_host:
        for candidate in origins:
            if urlsplit(candidate).netloc.lower() == fwd_host:
                origin = candidate
                break
    return f"{origin.rstrip('/')}{request.url.path}"


async def _check_token(request: Request, db: AsyncSession) -> sessions.AuthedRequest:
    """Verify the DPoP-bound access token (JWT + proof + session liveness + IP)."""
    try:
        return await sessions.check_request(
            db,
            authorization=request.headers.get("authorization"),
            dpop_proof=request.headers.get("dpop"),
            htm=request.method,
            htu=_expected_htu(request),
            source_ip=client_ip(request),
            now=datetime.now(UTC),
        )
    except sessions.RequestAuthError as exc:
        raise HTTPException(
            status_code=401,
            detail=exc.error,
            headers={"WWW-Authenticate": f'DPoP error="{exc.error}", algs="ES256"'},
        ) from exc


async def require_admin(request: Request, db: DbDep) -> sessions.AuthedRequest:
    require_lan_client(request)
    authed = await _check_token(request, db)
    # Tier is the frozen login-time value on the session, not a role lookup.
    if authed.session.auth_tier != "admin" or authed.user.auth_tier != "admin":
        raise HTTPException(status_code=403, detail="admin tier required")
    return authed


async def require_user(request: Request, db: DbDep) -> sessions.AuthedRequest:
    """Any authenticated user (standard or admin tier), no LAN restriction.

    For the standard-user portal endpoints, which are internet-facing via the
    portal host. Authorization beyond authentication is the endpoint's job.
    """
    return await _check_token(request, db)


async def require_portal_admin(request: Request, db: DbDep) -> sessions.AuthedRequest:
    """Admin tier without the LAN check, for portal review actions.

    Admins approve/deny standard users' download requests from the portal,
    which is reachable from the internet, so require_lan_client deliberately
    does not apply. The management API proper stays behind require_admin.
    """
    authed = await _check_token(request, db)
    if authed.session.auth_tier != "admin" or authed.user.auth_tier != "admin":
        raise HTTPException(status_code=403, detail="admin tier required")
    return authed


AdminDep = Annotated[sessions.AuthedRequest, Depends(require_admin)]
UserDep = Annotated[sessions.AuthedRequest, Depends(require_user)]
PortalAdminDep = Annotated[sessions.AuthedRequest, Depends(require_portal_admin)]


async def require_recent_stepup(authed: AdminDep) -> sessions.AuthedRequest:
    """Sensitive actions need a fresh WebAuthn assertion regardless of session age."""
    max_age = timedelta(seconds=get_settings().stepup_max_age)
    verified = authed.session.step_up_verified_at
    if verified is None or datetime.now(UTC) - verified > max_age:
        raise HTTPException(status_code=403, detail="stepup_required")
    return authed


StepUpDep = Annotated[sessions.AuthedRequest, Depends(require_recent_stepup)]

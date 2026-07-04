"""Admin API auth: DPoP-bound access token + admin tier, step-up for mutations.

The admin API is a resource server for the IdP's tokens and runs the same
check_request contract (JWT + DPoP + session liveness + IP binding). It is
never internet-facing: LAN/WireGuard only (docs/admin-access.md).
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core.netutil import resolve_client_ip
from hyproxy.db.engine import get_db
from hyproxy.idp import sessions

DbDep = Annotated[AsyncSession, Depends(get_db)]


def client_ip(request: Request) -> str:
    return resolve_client_ip(request)


def _expected_htu(request: Request) -> str:
    """DPoP htu for admin API calls, pinned to the public admin origin.

    The SPA signs the proof over its own origin (window.location.origin +
    /api/v1/...). Behind the data-plane proxy the Host header is rewritten to
    the internal backend vhost, and uvicorn's --proxy-headers honors
    X-Forwarded-Proto but not X-Forwarded-Host, so str(request.url) carries the
    wrong host and every proof would fail htu comparison. Rebuild htu from the
    configured admin_ui_origin (mirrors the IdP's _token_htu); the path is the
    one part of the request URL that is authoritative. Fall back to the raw URL
    when no origin is configured (dev / no proxy), where they already agree.
    """
    origin = get_settings().admin_ui_origin
    if not origin:
        return str(request.url)
    return f"{origin.rstrip('/')}{request.url.path}"


async def require_admin(request: Request, db: DbDep) -> sessions.AuthedRequest:
    try:
        authed = await sessions.check_request(
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
    # Tier is the frozen login-time value on the session, not a role lookup.
    if authed.session.auth_tier != "admin" or authed.user.auth_tier != "admin":
        raise HTTPException(status_code=403, detail="admin tier required")
    return authed


AdminDep = Annotated[sessions.AuthedRequest, Depends(require_admin)]


async def require_recent_stepup(authed: AdminDep) -> sessions.AuthedRequest:
    """Sensitive actions need a fresh WebAuthn assertion regardless of session age."""
    max_age = timedelta(seconds=get_settings().stepup_max_age)
    verified = authed.session.step_up_verified_at
    if verified is None or datetime.now(UTC) - verified > max_age:
        raise HTTPException(status_code=403, detail="stepup_required")
    return authed


StepUpDep = Annotated[sessions.AuthedRequest, Depends(require_recent_stepup)]

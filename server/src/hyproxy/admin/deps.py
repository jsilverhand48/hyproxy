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
from hyproxy.db.engine import get_db
from hyproxy.idp import sessions

DbDep = Annotated[AsyncSession, Depends(get_db)]


def client_ip(request: Request) -> str:
    assert request.client is not None
    return request.client.host


async def require_admin(request: Request, db: DbDep) -> sessions.AuthedRequest:
    try:
        authed = await sessions.check_request(
            db,
            authorization=request.headers.get("authorization"),
            dpop_proof=request.headers.get("dpop"),
            htm=request.method,
            htu=str(request.url),
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

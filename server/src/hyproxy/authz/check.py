"""POST /authz/check: the single authorization decision point for the data
plane (transport-agnostic; spec sections 2, 5, 11).

Every request the data plane wants to proxy comes here first. The response
tells it to allow (with identity headers to inject), deny, or bounce the
browser to the gateway login. Every decision is written to audit_log in the
same transaction.
"""

from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.authz.decision import evaluate_access
from hyproxy.authz.gateway import resolve_gateway_session
from hyproxy.config import get_settings
from hyproxy.db.engine import get_db
from hyproxy.db.models import AuditLog, Resource, User

router = APIRouter()

DbDep = Annotated[AsyncSession, Depends(get_db)]


class CheckRequest(BaseModel):
    host: str
    method: str
    uri: str  # path + optional query, as received
    source_ip: str
    backend_port: int | None = None
    gateway_cookie: str | None = None


class CheckResponse(BaseModel):
    decision: str  # "allow" | "deny" | "auth_required"
    reason: str = ""
    headers: dict[str, str] = {}
    redirect: str = ""


async def _audit(
    db: AsyncSession,
    *,
    user_id: object,
    resource_id: object,
    port: int | None,
    decision: str,
    reason: str,
    source_ip: str,
) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            resource_id=resource_id,
            port=port,
            decision=decision,
            reason=reason,
            source_ip=source_ip,
        )
    )
    await db.flush()


@router.post("/authz/check")
async def check(body: CheckRequest, db: DbDep) -> CheckResponse:
    settings = get_settings()
    now = datetime.now(UTC)
    host = body.host.strip().lower().rstrip(".")

    resource = await db.scalar(
        select(Resource).where(Resource.public_host == host, Resource.enabled.is_(True))
    )
    if resource is None:
        await _audit(
            db,
            user_id=None,
            resource_id=None,
            port=body.backend_port,
            decision="deny",
            reason="unknown_resource",
            source_ip=body.source_ip,
        )
        return CheckResponse(decision="deny", reason="unknown_resource")

    gw = await resolve_gateway_session(db, body.gateway_cookie, source_ip=body.source_ip, now=now)
    if gw is None:
        original = f"{settings.external_scheme}://{host}{body.uri or '/'}"
        redirect = (
            f"{settings.external_scheme}://{settings.auth_host}"
            f"/gateway/start?rd={quote(original, safe='')}"
        )
        await _audit(
            db,
            user_id=None,
            resource_id=resource.id,
            port=body.backend_port,
            decision="deny",
            reason="unauthenticated",
            source_ip=body.source_ip,
        )
        return CheckResponse(decision="auth_required", reason="unauthenticated", redirect=redirect)

    user = await db.get(User, gw.user_id)
    if user is None or user.status != "active":
        await _audit(
            db,
            user_id=gw.user_id,
            resource_id=resource.id,
            port=body.backend_port,
            decision="deny",
            reason="user_inactive",
            source_ip=body.source_ip,
        )
        return CheckResponse(decision="deny", reason="user_inactive")

    port = body.backend_port or (resource.ports[0] if resource.ports else 0)
    path = (body.uri or "/").split("?", 1)[0]
    access = await evaluate_access(
        db, user_id=user.id, resource_id=resource.id, port=port, path=path, now=now
    )
    decision = access.decision

    await _audit(
        db,
        user_id=user.id,
        resource_id=resource.id,
        port=port,
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        source_ip=body.source_ip,
    )
    if not decision.allowed:
        return CheckResponse(decision="deny", reason=decision.reason)
    return CheckResponse(
        decision="allow",
        reason=decision.reason,
        headers={
            "X-Forwarded-User": user.email,
            "X-Auth-User-Id": user.external_id,
            "X-Auth-Roles": ",".join(access.role_names),
        },
    )

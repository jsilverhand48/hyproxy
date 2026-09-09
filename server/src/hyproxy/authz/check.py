"""POST /authz/check: the single authorization decision point for the data
plane (transport-agnostic; spec sections 2, 5, 11).

Every request the data plane wants to proxy comes here first. The response
tells it to allow (with identity headers to inject), deny, 404, or bounce the
browser to the gateway login. Every decision is written to audit_log in the
same transaction.

A resource with `public_access` set takes a separate branch (_check_public) that
never consults the IdP, roles, or Policy: it is gated only by a shared password
held in a PublicSession cookie, and only the paths in `public_paths` exist at
all. See authz/publicgate.py.
"""

from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.authz.decision import evaluate_access
from hyproxy.authz.gateway import resolve_gateway_session
from hyproxy.authz.publicgate import PUBLIC_GATE_PATH, resolve_public_session
from hyproxy.config import get_settings
from hyproxy.db.engine import get_db
from hyproxy.db.models import AuditLog, Resource, User
from hyproxy.policy import pathglob

router = APIRouter()

DbDep = Annotated[AsyncSession, Depends(get_db)]


class CheckRequest(BaseModel):
    host: str
    method: str
    uri: str  # path + optional query, as received
    source_ip: str
    backend_port: int | None = None
    gateway_cookie: str | None = None
    # Access cookie for a password-gated public resource, extracted and
    # stripped by the data plane exactly like gateway_cookie.
    public_cookie: str | None = None


class CheckResponse(BaseModel):
    # "not_found" makes the data plane return a bare 404. It exists so a public
    # resource can hide every path outside its allowlist without confirming that
    # the hostname serves anything at all.
    decision: str  # "allow" | "deny" | "auth_required" | "not_found"
    reason: str = ""
    headers: dict[str, str] = {}
    redirect: str = ""
    # Data-plane cache hint: "host" only on allow decisions that provably
    # hold for every path/time on this host (see decision.host_stable).
    # Denies and constrained allows stay "none" and are re-checked per request.
    cache_scope: str = "none"  # "host" | "none"
    cache_ttl_secs: int = 0


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


def _admin_console_host() -> str | None:
    """Host of the admin console (React SPA), derived from admin_ui_origin.
    None when no admin UI is wired, so nothing is treated as the console."""
    origin = get_settings().admin_ui_origin
    if not origin:
        return None
    return (urlsplit(origin).hostname or "").lower() or None


async def _check_public(
    db: AsyncSession,
    body: CheckRequest,
    resource: Resource,
    host: str,
    path: str,
    now: datetime,
) -> CheckResponse:
    """Decide a request against a password-gated public resource.

    Deliberately does NOT fall through to the normal path. A public resource has
    exactly one way in -- the shared password -- so a signed-in admin gets the
    same prompt as an anonymous visitor and no role or Policy row can widen what
    the link exposes.
    """
    settings = get_settings()

    # Paths outside the allowlist do not exist. 404 rather than 403 so a public
    # link is never a probe for what else the backend serves.
    if not pathglob.matches(resource.public_paths, path):
        await _audit(
            db,
            user_id=None,
            resource_id=resource.id,
            port=body.backend_port,
            decision="deny",
            reason="public_path_unmatched",
            source_ip=body.source_ip,
        )
        return CheckResponse(decision="not_found", reason="public_path_unmatched")

    session = await resolve_public_session(
        db,
        body.public_cookie,
        resource_id=resource.id,
        source_ip=body.source_ip,
        now=now,
    )
    if session is None:
        original = body.uri or "/"
        redirect = (
            f"{settings.external_scheme}://{host}{PUBLIC_GATE_PATH}"
            f"?rd={quote(original, safe='')}"
        )
        await _audit(
            db,
            user_id=None,
            resource_id=resource.id,
            port=body.backend_port,
            decision="deny",
            reason="public_unauthenticated",
            source_ip=body.source_ip,
        )
        return CheckResponse(
            decision="auth_required", reason="public_unauthenticated", redirect=redirect
        )

    await _audit(
        db,
        user_id=None,
        resource_id=resource.id,
        port=body.backend_port,
        decision="allow",
        reason="public_allowed",
        source_ip=body.source_ip,
    )
    # No identity headers: the backend must see a genuinely anonymous request
    # and must never be able to mistake a visitor for a real user. The data
    # plane has already stripped any client-supplied ones.
    #
    # cache_scope stays "none": the decision depends on the path, so it is never
    # host-stable, and public traffic must not skip the per-request check.
    return CheckResponse(decision="allow", reason="public_allowed")


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

    path = (body.uri or "/").split("?", 1)[0]
    if resource.public_access:
        return await _check_public(db, body, resource, host, path, now)

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

    # A standard-tier user must never be served the admin console; bounce the
    # browser to the signed-in page instead of evaluating resource policy.
    if user.auth_tier != "admin" and host == _admin_console_host():
        # /auth/done (which renders signedin.html) is an IdP route on the issuer
        # host, not the auth host; and the IdP session cookie is scoped to the
        # issuer, so the signed-in page must be fetched there.
        signed_in = f"{settings.issuer.rstrip('/')}/auth/done"
        await _audit(
            db,
            user_id=user.id,
            resource_id=resource.id,
            port=body.backend_port,
            decision="deny",
            reason="tier_forbidden",
            source_ip=body.source_ip,
        )
        return CheckResponse(
            decision="auth_required", reason="tier_forbidden", redirect=signed_in
        )

    port = body.backend_port or (resource.ports[0] if resource.ports else 0)
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
    cache_ttl = settings.authz_cache_ttl
    cacheable = access.host_stable and cache_ttl > 0
    return CheckResponse(
        decision="allow",
        reason=decision.reason,
        headers={
            "X-Forwarded-User": user.email,
            "X-Auth-User-Id": user.external_id,
            "X-Auth-Roles": ",".join(access.role_names),
        },
        cache_scope="host" if cacheable else "none",
        cache_ttl_secs=cache_ttl if cacheable else 0,
    )

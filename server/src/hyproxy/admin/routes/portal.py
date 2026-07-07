"""Standard-user portal: my resources, password change, P2P download requests.

Unlike the management routers, these endpoints are also served on the
internet-facing portal host, so they use require_user / require_portal_admin
(no LAN restriction, no WebAuthn step-up; see admin/deps.py).
"""

import uuid
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.admin import qbit
from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import DbDep, PortalAdminDep, UserDep, client_ip
from hyproxy.admin.routes.users import _revoke_user_sessions
from hyproxy.admin.schemas import (
    MAGNET_RE,
    DownloadRequestIn,
    DownloadRequestOut,
    MyResourceOut,
    PasswordChangeIn,
)
from hyproxy.audit.events import AuthEventType, emit
from hyproxy.config import get_settings
from hyproxy.db.models import DownloadRequest, Policy, Resource, User, UserRole
from hyproxy.idp import sessions
from hyproxy.security.passwords import hash_password, verify_password

router = APIRouter(prefix="/api/v1/portal", tags=["portal"])

def _qbit_failed() -> JSONResponse:
    return JSONResponse(
        status_code=502, content={"detail": "qbittorrent submission failed"}
    )


def _is_admin(authed: sessions.AuthedRequest) -> bool:
    return authed.session.auth_tier == "admin" and authed.user.auth_tier == "admin"


@router.get("/me/resources", response_model=list[MyResourceOut])
async def my_resources(db: DbDep, authed: UserDep) -> list[MyResourceOut]:
    """Resources the caller's roles are allowed to reach.

    Presentation-only listing: it ignores deny-policy overrides and port/path
    constraints that the authz decision engine applies per request. The data
    plane still authorizes every actual access.
    """
    rows = (
        await db.scalars(
            select(Resource)
            .join(Policy, Policy.resource_id == Resource.id)
            .join(UserRole, UserRole.role_id == Policy.role_id)
            .where(
                UserRole.user_id == authed.user.id,
                Policy.action == "allow",
                Policy.enabled.is_(True),
                Resource.enabled.is_(True),
            )
            .distinct()
            .order_by(Resource.name)
        )
    ).all()
    return [MyResourceOut.model_validate(r) for r in rows]


@router.post("/me/password", status_code=204, response_model=None)
async def change_password(
    body: PasswordChangeIn, request: Request, db: DbDep, authed: UserDep
) -> JSONResponse | None:
    """Self-service password change; every other session is signed out."""
    ip = client_ip(request)
    user = authed.user
    if not verify_password(user.password_hash, body.current_password):
        await emit(
            db,
            AuthEventType.USER_PASSWORD_CHANGE_FAILED,
            source_ip=ip,
            success=False,
            user_id=user.id,
            session_id=authed.session.id,
        )
        return JSONResponse(
            status_code=403, content={"detail": "current password incorrect"}
        )
    user.password_hash = hash_password(body.new_password)
    user.updated_at = datetime.now(UTC)
    await db.flush()
    await _revoke_user_sessions(
        db, user.id, ip, reason="password_change", exclude_session_id=authed.session.id
    )
    # No before/after snapshot: never record password material.
    await record_change(
        db,
        actor_id=user.id,
        entity_type="password_change",
        entity_id=user.id,
        action="update",
    )
    await emit(
        db,
        AuthEventType.USER_PASSWORD_CHANGED,
        source_ip=ip,
        success=True,
        user_id=user.id,
        session_id=authed.session.id,
    )
    return None


def _to_out(row: DownloadRequest, email: str | None) -> DownloadRequestOut:
    out = DownloadRequestOut.model_validate(row)
    out.user_email = email
    return out


@router.get("/downloads", response_model=list[DownloadRequestOut])
async def list_downloads(db: DbDep, authed: UserDep) -> list[DownloadRequestOut]:
    """Standard users see their own requests; admins see everyone's."""
    stmt = (
        select(DownloadRequest, User.email)
        .join(User, DownloadRequest.user_id == User.id)
        .order_by(DownloadRequest.created_at.desc())
        .limit(200)
    )
    if not _is_admin(authed):
        stmt = stmt.where(DownloadRequest.user_id == authed.user.id)
    rows = (await db.execute(stmt)).all()
    return [_to_out(req, email) for req, email in rows]


async def _submit(
    db: AsyncSession,
    row: DownloadRequest,
    reviewer_id: uuid.UUID,
    ip: str,
    qbit_http: httpx.AsyncClient,
) -> JSONResponse | None:
    """Send the request to qBittorrent and mark it approved.

    Returns a 502/503 response on failure, leaving the row pending with the
    error recorded (the transaction still commits), so an admin can retry via
    approve. None means success.
    """
    settings = get_settings()
    savepath = (
        settings.qbit_savepath_shows
        if row.target == "shows"
        else settings.qbit_savepath_movies
    )
    # Defense in depth: the value passed the schema validator at insert time,
    # but never place anything non-magnet in the urls field.
    if not savepath or not MAGNET_RE.match(row.magnet):
        row.error = "savepath not configured" if not savepath else "invalid magnet"
        await db.flush()
        return JSONResponse(
            status_code=503, content={"detail": f"download target unavailable: {row.error}"}
        )
    try:
        await qbit.add_torrent(qbit_http, magnet=row.magnet, savepath=savepath)
    except qbit.QbitError as exc:
        row.error = str(exc)
        await db.flush()
        await emit(
            db,
            AuthEventType.DOWNLOAD_SUBMIT_FAILED,
            source_ip=ip,
            success=False,
            user_id=reviewer_id,
            detail={"entity_id": str(row.id), "target": row.target, "reason": str(exc)[:256]},
        )
        return _qbit_failed()
    now = datetime.now(UTC)
    row.status = "approved"
    row.reviewed_by = reviewer_id
    row.reviewed_at = now
    row.submitted_at = now
    row.error = None
    await db.flush()
    await emit(
        db,
        AuthEventType.DOWNLOAD_SUBMITTED,
        source_ip=ip,
        success=True,
        user_id=reviewer_id,
        detail={"entity_id": str(row.id), "target": row.target},
    )
    return None


@router.post("/downloads", response_model=DownloadRequestOut, status_code=201)
async def create_download(
    body: DownloadRequestIn, request: Request, db: DbDep, authed: UserDep
) -> DownloadRequestOut | JSONResponse:
    """Standard users queue a pending request; admins submit immediately."""
    ip = client_ip(request)
    row = DownloadRequest(
        user_id=authed.user.id, magnet=body.magnet, target=body.target, status="pending"
    )
    db.add(row)
    await db.flush()
    # Load server defaults (id, created_at) before serializing; the async
    # session cannot lazy-refresh expired attributes later.
    await db.refresh(row)
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="download_request",
        entity_id=row.id,
        action="create",
        after={"target": row.target, "magnet": row.magnet[:256]},
    )
    if _is_admin(authed):
        failed = await _submit(db, row, authed.user.id, ip, request.app.state.qbit_http)
        if failed is not None:
            return failed
    else:
        await emit(
            db,
            AuthEventType.DOWNLOAD_REQUESTED,
            source_ip=ip,
            success=True,
            user_id=authed.user.id,
            detail={"entity_id": str(row.id), "target": row.target},
        )
    return _to_out(row, authed.user.email)


async def _pending_or_error(
    db: AsyncSession, request_id: uuid.UUID
) -> DownloadRequest | JSONResponse:
    # FOR UPDATE so two admins reviewing at once cannot double-submit.
    row = await db.get(DownloadRequest, request_id, with_for_update=True)
    if row is None:
        return JSONResponse(status_code=404, content={"detail": "request not found"})
    if row.status != "pending":
        return JSONResponse(
            status_code=409, content={"detail": f"request already {row.status}"}
        )
    return row


@router.post("/downloads/{request_id}/approve", response_model=DownloadRequestOut)
async def approve_download(
    request_id: uuid.UUID, request: Request, db: DbDep, authed: PortalAdminDep
) -> DownloadRequestOut | JSONResponse:
    row = await _pending_or_error(db, request_id)
    if isinstance(row, JSONResponse):
        return row
    ip = client_ip(request)
    failed = await _submit(db, row, authed.user.id, ip, request.app.state.qbit_http)
    if failed is not None:
        return failed
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="download_request",
        entity_id=row.id,
        action="update",
        after={"status": "approved"},
    )
    await emit(
        db,
        AuthEventType.DOWNLOAD_APPROVED,
        source_ip=ip,
        success=True,
        user_id=authed.user.id,
        detail={"entity_id": str(row.id), "target": row.target},
    )
    email = await db.scalar(select(User.email).where(User.id == row.user_id))
    return _to_out(row, email)


@router.post("/downloads/{request_id}/deny", response_model=DownloadRequestOut)
async def deny_download(
    request_id: uuid.UUID, request: Request, db: DbDep, authed: PortalAdminDep
) -> DownloadRequestOut | JSONResponse:
    row = await _pending_or_error(db, request_id)
    if isinstance(row, JSONResponse):
        return row
    row.status = "denied"
    row.reviewed_by = authed.user.id
    row.reviewed_at = datetime.now(UTC)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="download_request",
        entity_id=row.id,
        action="update",
        after={"status": "denied"},
    )
    await emit(
        db,
        AuthEventType.DOWNLOAD_DENIED,
        source_ip=client_ip(request),
        success=True,
        user_id=authed.user.id,
        detail={"entity_id": str(row.id), "target": row.target},
    )
    email = await db.scalar(select(User.email).where(User.id == row.user_id))
    return _to_out(row, email)

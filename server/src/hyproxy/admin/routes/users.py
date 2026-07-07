import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import AdminDep, DbDep, StepUpDep, client_ip
from hyproxy.admin.schemas import (
    CredentialOut,
    PasswordResetIn,
    SessionOut,
    UserCreate,
    UserOut,
    UserPatch,
)
from hyproxy.audit.events import AuthEventType, emit
from hyproxy.db.models import (
    RecoveryCode,
    Session,
    User,
    UserTotp,
    WebAuthnCredential,
)
from hyproxy.idp import sessions as session_service
from hyproxy.idp.oidc import refresh as refresh_service
from hyproxy.security.passwords import hash_password

router = APIRouter(prefix="/api/v1/users", tags=["users"])


def _user_snapshot(user: User) -> dict[str, str]:
    return {
        "email": user.email,
        "display_name": user.display_name,
        "status": user.status,
        "auth_tier": user.auth_tier,
    }


async def _get_user_or_404(db: AsyncSession, user_id: uuid.UUID) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return user


async def _strong_credential_count(db: AsyncSession, user_id: uuid.UUID) -> int:
    count = await db.scalar(
        select(func.count())
        .select_from(WebAuthnCredential)
        .where(
            WebAuthnCredential.user_id == user_id,
            WebAuthnCredential.break_glass.is_(False),
        )
    )
    return int(count or 0)


async def _revoke_user_sessions(
    db: AsyncSession,
    user_id: uuid.UUID,
    ip: str,
    *,
    reason: str = "admin_action",
    exclude_session_id: uuid.UUID | None = None,
) -> None:
    stmt = select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
    if exclude_session_id is not None:
        stmt = stmt.where(Session.id != exclude_session_id)
    rows = (await db.scalars(stmt)).all()
    for row in rows:
        await refresh_service.revoke_for_session(db, row.id)
        await session_service.revoke(db, row, reason=reason, source_ip=ip)


@router.get("")
async def list_users(db: DbDep, _authed: AdminDep) -> list[UserOut]:
    users = (await db.scalars(select(User).order_by(User.created_at))).all()
    return [UserOut.model_validate(u) for u in users]


@router.get("/{user_id}")
async def get_user(user_id: uuid.UUID, db: DbDep, _authed: AdminDep) -> UserOut:
    return UserOut.model_validate(await _get_user_or_404(db, user_id))


@router.post("", status_code=201)
async def create_user(body: UserCreate, db: DbDep, authed: StepUpDep) -> UserOut:
    existing = await db.scalar(select(User).where(User.email == body.email))
    if existing is not None:
        raise HTTPException(status_code=409, detail="email already exists")
    user = User(
        external_id=f"user-{uuid.uuid4()}",
        email=body.email,
        display_name=body.display_name,
        status="active",
        auth_tier=body.auth_tier,
        password_hash=hash_password(body.temp_password),
    )
    db.add(user)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="user",
        entity_id=user.id,
        action="create",
        after=_user_snapshot(user),
    )
    return UserOut.model_validate(user)


@router.patch("/{user_id}")
async def patch_user(
    user_id: uuid.UUID, body: UserPatch, request: Request, db: DbDep, authed: StepUpDep
) -> UserOut:
    user = await _get_user_or_404(db, user_id)
    before = _user_snapshot(user)

    new_tier = body.auth_tier or user.auth_tier
    new_status = body.status or user.status
    if user.is_protected and (new_status == "disabled" or new_tier != "admin"):
        raise HTTPException(
            status_code=409,
            detail="the bootstrap admin cannot be disabled or demoted",
        )
    # Invariant: promoting to admin tier requires two strong (non-break-glass)
    # authenticators already enrolled; otherwise password alone could take over.
    if new_tier == "admin" and user.auth_tier != "admin":
        if await _strong_credential_count(db, user.id) < 2:
            raise HTTPException(
                status_code=409,
                detail="admin tier requires two enrolled non-break-glass passkeys",
            )
    if body.display_name is not None:
        user.display_name = body.display_name
    user.auth_tier = new_tier
    user.status = new_status
    user.updated_at = datetime.now(UTC)
    await db.flush()

    if before["status"] == "active" and user.status == "disabled":
        await _revoke_user_sessions(db, user.id, client_ip(request))
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="user",
        entity_id=user.id,
        action="update",
        before=before,
        after=_user_snapshot(user),
    )
    return UserOut.model_validate(user)


@router.delete("/{user_id}", status_code=204)
async def delete_user(user_id: uuid.UUID, request: Request, db: DbDep, authed: StepUpDep) -> None:
    user = await _get_user_or_404(db, user_id)
    if user.id == authed.user.id:
        raise HTTPException(status_code=409, detail="cannot delete yourself")
    if user.is_protected:
        raise HTTPException(status_code=409, detail="the bootstrap admin cannot be deleted")
    before = _user_snapshot(user)
    await _revoke_user_sessions(db, user.id, client_ip(request))
    await db.delete(user)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="user",
        entity_id=user_id,
        action="delete",
        before=before,
    )


@router.get("/{user_id}/credentials")
async def list_credentials(user_id: uuid.UUID, db: DbDep, _authed: AdminDep) -> list[CredentialOut]:
    await _get_user_or_404(db, user_id)
    rows = (
        await db.scalars(
            select(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == user_id)
            .order_by(WebAuthnCredential.created_at)
        )
    ).all()
    return [CredentialOut.model_validate(r) for r in rows]


@router.delete("/{user_id}/credentials/{credential_id}", status_code=204)
async def delete_credential(
    user_id: uuid.UUID, credential_id: uuid.UUID, db: DbDep, authed: StepUpDep
) -> None:
    user = await _get_user_or_404(db, user_id)
    row = await db.get(WebAuthnCredential, credential_id)
    if row is None or row.user_id != user_id:
        raise HTTPException(status_code=404, detail="credential not found")
    # Invariant: an active admin keeps at least two strong authenticators.
    if user.auth_tier == "admin" and user.status == "active" and not row.break_glass:
        if await _strong_credential_count(db, user_id) <= 2:
            raise HTTPException(
                status_code=409,
                detail="active admin must keep two non-break-glass passkeys",
            )
    await db.delete(row)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="webauthn_credential",
        entity_id=credential_id,
        action="delete",
        before={"friendly_name": row.friendly_name, "user_id": str(user_id)},
    )


@router.get("/{user_id}/sessions")
async def list_sessions(user_id: uuid.UUID, db: DbDep, _authed: AdminDep) -> list[SessionOut]:
    await _get_user_or_404(db, user_id)
    rows = (
        await db.scalars(
            select(Session).where(Session.user_id == user_id).order_by(Session.issued_at.desc())
        )
    ).all()
    return [SessionOut.model_validate(r) for r in rows]


@router.post("/{user_id}/sessions/revoke", status_code=204)
async def revoke_sessions(
    user_id: uuid.UUID, request: Request, db: DbDep, authed: StepUpDep
) -> None:
    await _get_user_or_404(db, user_id)
    await _revoke_user_sessions(db, user_id, client_ip(request))
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="session",
        entity_id=user_id,
        action="update",
        after={"revoked": "all"},
    )


@router.post("/{user_id}/reset-totp", status_code=204)
async def reset_totp(user_id: uuid.UUID, request: Request, db: DbDep, authed: StepUpDep) -> None:
    """Admin-assisted TOTP reset: drop secret + unused recovery codes, revoke
    sessions; the user re-enrolls at next login."""
    user = await _get_user_or_404(db, user_id)
    if user.auth_tier == "admin":
        raise HTTPException(status_code=409, detail="admin accounts do not use TOTP")
    ip = client_ip(request)
    await db.execute(delete(UserTotp).where(UserTotp.user_id == user_id))
    await db.execute(
        delete(RecoveryCode).where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
    )
    await _revoke_user_sessions(db, user_id, ip)
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="totp_reset",
        entity_id=user_id,
        action="update",
    )
    await emit(
        db,
        AuthEventType.ADMIN_TOTP_RESET,
        source_ip=ip,
        success=True,
        user_id=user_id,
        detail={"entity_id": str(user_id)},
    )


@router.post("/{user_id}/reset-password", status_code=204)
async def reset_password(
    user_id: uuid.UUID,
    body: PasswordResetIn,
    request: Request,
    db: DbDep,
    authed: StepUpDep,
) -> None:
    """Admin-assisted password reset: set a new temporary password and revoke
    all sessions; the user signs in with the new password."""
    user = await _get_user_or_404(db, user_id)
    ip = client_ip(request)
    user.password_hash = hash_password(body.temp_password)
    user.updated_at = datetime.now(UTC)
    await db.flush()
    await _revoke_user_sessions(db, user_id, ip)
    # No before/after snapshot: never record password material.
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="password_reset",
        entity_id=user_id,
        action="update",
    )
    await emit(
        db,
        AuthEventType.ADMIN_PASSWORD_RESET,
        source_ip=ip,
        success=True,
        user_id=user_id,
        detail={"entity_id": str(user_id)},
    )

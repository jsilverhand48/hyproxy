import uuid

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import AdminDep, DbDep, StepUpDep
from hyproxy.db.models import Role, User, UserRole

router = APIRouter(prefix="/api/v1/users/{user_id}/roles", tags=["user_roles"])


@router.get("")
async def list_user_roles(user_id: uuid.UUID, db: DbDep, _authed: AdminDep) -> list[str]:
    if await db.get(User, user_id) is None:
        raise HTTPException(status_code=404, detail="user not found")
    rows = (
        await db.scalars(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
        )
    ).all()
    return list(rows)


@router.put("/{role_id}", status_code=204)
async def attach_role(user_id: uuid.UUID, role_id: uuid.UUID, db: DbDep, authed: StepUpDep) -> None:
    if await db.get(User, user_id) is None or await db.get(Role, role_id) is None:
        raise HTTPException(status_code=404, detail="user or role not found")
    if await db.get(UserRole, (user_id, role_id)) is None:
        db.add(UserRole(user_id=user_id, role_id=role_id))
        await db.flush()
        await record_change(
            db,
            actor_id=authed.user.id,
            entity_type="user_role",
            entity_id=user_id,
            action="create",
            after={"role_id": str(role_id)},
        )


@router.delete("/{role_id}", status_code=204)
async def detach_role(user_id: uuid.UUID, role_id: uuid.UUID, db: DbDep, authed: StepUpDep) -> None:
    row = await db.get(UserRole, (user_id, role_id))
    if row is None:
        raise HTTPException(status_code=404, detail="assignment not found")
    await db.delete(row)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="user_role",
        entity_id=user_id,
        action="delete",
        before={"role_id": str(role_id)},
    )

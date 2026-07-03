import uuid

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import AdminDep, DbDep, StepUpDep
from hyproxy.admin.schemas import RoleCreate, RoleOut, UserOut
from hyproxy.db.models import Role, User, UserRole

router = APIRouter(prefix="/api/v1/roles", tags=["roles"])


@router.get("")
async def list_roles(db: DbDep, _authed: AdminDep) -> list[RoleOut]:
    rows = (await db.scalars(select(Role).order_by(Role.name))).all()
    return [RoleOut.model_validate(r) for r in rows]


@router.get("/{role_id}/users")
async def list_role_users(role_id: uuid.UUID, db: DbDep, _authed: AdminDep) -> list[UserOut]:
    if await db.get(Role, role_id) is None:
        raise HTTPException(status_code=404, detail="role not found")
    rows = (
        await db.scalars(
            select(User)
            .join(UserRole, UserRole.user_id == User.id)
            .where(UserRole.role_id == role_id)
            .order_by(User.email)
        )
    ).all()
    return [UserOut.model_validate(u) for u in rows]


@router.post("", status_code=201)
async def create_role(body: RoleCreate, db: DbDep, authed: StepUpDep) -> RoleOut:
    if await db.scalar(select(Role).where(Role.name == body.name)) is not None:
        raise HTTPException(status_code=409, detail="role name exists")
    role = Role(name=body.name, description=body.description)
    db.add(role)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="role",
        entity_id=role.id,
        action="create",
        after={"name": role.name},
    )
    return RoleOut.model_validate(role)


@router.delete("/{role_id}", status_code=204)
async def delete_role(role_id: uuid.UUID, db: DbDep, authed: StepUpDep) -> None:
    role = await db.get(Role, role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="role not found")
    await db.delete(role)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="role",
        entity_id=role_id,
        action="delete",
        before={"name": role.name},
    )

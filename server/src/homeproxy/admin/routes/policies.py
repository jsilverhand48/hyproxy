import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import AdminDep, DbDep, StepUpDep
from hyproxy.admin.schemas import PolicyCreate, PolicyOut, PolicyPatch
from hyproxy.db.models import Policy, Resource, Role

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


def _snapshot(p: Policy) -> dict[str, Any]:
    return {
        "role_id": str(p.role_id),
        "resource_id": str(p.resource_id),
        "action": p.action,
        "allowed_ports": p.allowed_ports,
        "allowed_paths": p.allowed_paths,
        "conditions_json": p.conditions_json,
        "enabled": p.enabled,
    }


@router.get("")
async def list_policies(db: DbDep, _authed: AdminDep) -> list[PolicyOut]:
    rows = (await db.scalars(select(Policy).order_by(Policy.created_at))).all()
    return [PolicyOut.model_validate(r) for r in rows]


@router.post("", status_code=201)
async def create_policy(body: PolicyCreate, db: DbDep, authed: StepUpDep) -> PolicyOut:
    if await db.get(Role, body.role_id) is None:
        raise HTTPException(status_code=404, detail="role not found")
    if await db.get(Resource, body.resource_id) is None:
        raise HTTPException(status_code=404, detail="resource not found")
    row = Policy(**body.model_dump())
    db.add(row)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="policy",
        entity_id=row.id,
        action="create",
        after=_snapshot(row),
    )
    return PolicyOut.model_validate(row)


@router.patch("/{policy_id}")
async def patch_policy(
    policy_id: uuid.UUID, body: PolicyPatch, db: DbDep, authed: StepUpDep
) -> PolicyOut:
    row = await db.get(Policy, policy_id)
    if row is None:
        raise HTTPException(status_code=404, detail="policy not found")
    before = _snapshot(row)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="policy",
        entity_id=policy_id,
        action="update",
        before=before,
        after=_snapshot(row),
    )
    return PolicyOut.model_validate(row)


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(policy_id: uuid.UUID, db: DbDep, authed: StepUpDep) -> None:
    row = await db.get(Policy, policy_id)
    if row is None:
        raise HTTPException(status_code=404, detail="policy not found")
    before = _snapshot(row)
    await db.delete(row)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="policy",
        entity_id=policy_id,
        action="delete",
        before=before,
    )

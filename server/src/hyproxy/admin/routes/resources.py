import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import AdminDep, DbDep, StepUpDep
from hyproxy.admin.schemas import ResourceCreate, ResourceOut, ResourcePatch
from hyproxy.db.models import Resource

router = APIRouter(prefix="/api/v1/resources", tags=["resources"])


def _snapshot(r: Resource) -> dict[str, Any]:
    return {
        "name": r.name,
        "protocol": r.protocol,
        "host": r.host,
        "ports": r.ports,
        "path_prefix": r.path_prefix,
        "enabled": r.enabled,
    }


@router.get("")
async def list_resources(db: DbDep, _authed: AdminDep) -> list[ResourceOut]:
    rows = (await db.scalars(select(Resource).order_by(Resource.name))).all()
    return [ResourceOut.model_validate(r) for r in rows]


@router.post("", status_code=201)
async def create_resource(body: ResourceCreate, db: DbDep, authed: StepUpDep) -> ResourceOut:
    if await db.scalar(select(Resource).where(Resource.name == body.name)) is not None:
        raise HTTPException(status_code=409, detail="resource name exists")
    row = Resource(**body.model_dump())
    db.add(row)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="resource",
        entity_id=row.id,
        action="create",
        after=_snapshot(row),
    )
    return ResourceOut.model_validate(row)


@router.patch("/{resource_id}")
async def patch_resource(
    resource_id: uuid.UUID, body: ResourcePatch, db: DbDep, authed: StepUpDep
) -> ResourceOut:
    row = await db.get(Resource, resource_id)
    if row is None:
        raise HTTPException(status_code=404, detail="resource not found")
    before = _snapshot(row)
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(row, field, value)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="resource",
        entity_id=resource_id,
        action="update",
        before=before,
        after=_snapshot(row),
    )
    return ResourceOut.model_validate(row)


@router.delete("/{resource_id}", status_code=204)
async def delete_resource(resource_id: uuid.UUID, db: DbDep, authed: StepUpDep) -> None:
    row = await db.get(Resource, resource_id)
    if row is None:
        raise HTTPException(status_code=404, detail="resource not found")
    before = _snapshot(row)
    await db.delete(row)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="resource",
        entity_id=resource_id,
        action="delete",
        before=before,
    )

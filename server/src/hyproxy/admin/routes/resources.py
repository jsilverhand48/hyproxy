import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import AdminDep, DbDep, StepUpDep
from hyproxy.admin.schemas import GUAC_PROTOCOLS, ResourceCreate, ResourceOut, ResourcePatch
from hyproxy.config import get_settings
from hyproxy.core import secrets
from hyproxy.db.models import Resource, ResourceConnection
from hyproxy.guac.connections import seal_secret_params

router = APIRouter(prefix="/api/v1/resources", tags=["resources"])


def _snapshot(r: Resource) -> dict[str, Any]:
    return {
        "name": r.name,
        "protocol": r.protocol,
        "public_host": r.public_host,
        "host": r.host,
        "ports": r.ports,
        "path_prefix": r.path_prefix,
        "enabled": r.enabled,
    }


async def _validate_public_host(
    db: DbDep, public_host: str | None, *, exclude_id: uuid.UUID | None = None
) -> None:
    """Reject a public_host that collides with the gateway auth host or another
    resource. Format is already normalized/validated by the schema; the data
    plane resolves routes by this host, so a duplicate would be ambiguous."""
    if public_host is None:
        return
    if public_host == get_settings().auth_host.strip().lower().rstrip("."):
        raise HTTPException(status_code=409, detail="public_host is reserved (auth host)")
    query = select(Resource.id).where(Resource.public_host == public_host)
    if exclude_id is not None:
        query = query.where(Resource.id != exclude_id)
    if await db.scalar(query) is not None:
        raise HTTPException(status_code=409, detail="public_host already in use")


@router.get("")
async def list_resources(db: DbDep, _authed: AdminDep) -> list[ResourceOut]:
    rows = (await db.scalars(select(Resource).order_by(Resource.name))).all()
    return [ResourceOut.model_validate(r) for r in rows]


@router.post("", status_code=201)
async def create_resource(body: ResourceCreate, db: DbDep, authed: StepUpDep) -> ResourceOut:
    if await db.scalar(select(Resource).where(Resource.name == body.name)) is not None:
        raise HTTPException(status_code=409, detail="resource name exists")
    await _validate_public_host(db, body.public_host)
    fields = body.model_dump(exclude={"connection"})
    if body.connection is not None:
        # Policy-facing host/ports mirror the guacd target so there is a single
        # source of truth in the UI.
        fields["host"] = body.connection.hostname
        fields["ports"] = [body.connection.port]
    row = Resource(**fields)
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
    if body.connection is not None:
        conn = ResourceConnection(
            resource_id=row.id,
            protocol=body.protocol,
            hostname=body.connection.hostname,
            port=body.connection.port,
            params_json=body.connection.params,
            secret_keys=[],
        )
        if body.connection.secret_params:
            backend = secrets.get_secrets_backend()
            key_id, blob, keys = seal_secret_params(backend, body.connection.secret_params)
            conn.key_id, conn.secret_ciphertext, conn.secret_keys = key_id, blob, keys
        db.add(conn)
        await db.flush()
        await record_change(
            db,
            actor_id=authed.user.id,
            entity_type="resource_connection",
            entity_id=conn.id,
            action="create",
            after={
                "protocol": conn.protocol,
                "hostname": conn.hostname,
                "port": conn.port,
                "params": conn.params_json,
                "secret_keys": list(conn.secret_keys),
                "has_secret": conn.secret_ciphertext is not None,
            },
        )
    return ResourceOut.model_validate(row)


@router.patch("/{resource_id}")
async def patch_resource(
    resource_id: uuid.UUID, body: ResourcePatch, db: DbDep, authed: StepUpDep
) -> ResourceOut:
    row = await db.get(Resource, resource_id)
    if row is None:
        raise HTTPException(status_code=404, detail="resource not found")
    patch = body.model_dump(exclude_unset=True)
    if "public_host" in patch:
        if patch["public_host"] is not None and row.protocol in GUAC_PROTOCOLS:
            raise HTTPException(
                status_code=422,
                detail="guac resources use the portal tunnel and cannot have a public_host",
            )
        await _validate_public_host(db, patch["public_host"], exclude_id=resource_id)
    before = _snapshot(row)
    for field, value in patch.items():
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

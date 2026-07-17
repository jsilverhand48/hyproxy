"""Per-resource Guacamole connection config (Phase 4).

One connection per resource, nested under the resource. Secret parameters are
sealed at rest and are write-only: reads return only the secret parameter NAMES
(`secret_keys`), never values. Mutations require step-up and are change-logged
(the log records no secret values).
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from hyproxy.admin.changes import record_change
from hyproxy.admin.deps import AdminDep, DbDep, StepUpDep
from hyproxy.admin.schemas import ResourceConnectionOut, ResourceConnectionUpsert
from hyproxy.core import secrets
from hyproxy.db.models import Resource, ResourceConnection
from hyproxy.guac.connections import seal_secret_params

router = APIRouter(prefix="/api/v1/resources", tags=["connections"])


def _out(row: ResourceConnection) -> ResourceConnectionOut:
    return ResourceConnectionOut(
        id=row.id,
        resource_id=row.resource_id,
        protocol=row.protocol,
        hostname=row.hostname,
        port=row.port,
        params=row.params_json,
        secret_keys=list(row.secret_keys),
        has_secret=row.secret_ciphertext is not None,
    )


def _snapshot(row: ResourceConnection) -> dict[str, Any]:
    # No secret VALUES here; only names, so the change log never leaks secrets.
    return {
        "protocol": row.protocol,
        "hostname": row.hostname,
        "port": row.port,
        "params": row.params_json,
        "secret_keys": list(row.secret_keys),
        "has_secret": row.secret_ciphertext is not None,
    }


async def _load(db: DbDep, resource_id: uuid.UUID) -> ResourceConnection | None:
    row: ResourceConnection | None = await db.scalar(
        select(ResourceConnection).where(ResourceConnection.resource_id == resource_id)
    )
    return row


@router.get("/{resource_id}/connection")
async def get_connection(
    resource_id: uuid.UUID, db: DbDep, _authed: AdminDep
) -> ResourceConnectionOut:
    row = await _load(db, resource_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no connection configured")
    return _out(row)


@router.put("/{resource_id}/connection")
async def put_connection(
    resource_id: uuid.UUID,
    body: ResourceConnectionUpsert,
    db: DbDep,
    authed: StepUpDep,
) -> ResourceConnectionOut:
    resource = await db.get(Resource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="resource not found")
    row = await _load(db, resource_id)
    creating = row is None
    before = None if creating else _snapshot(row)  # type: ignore[arg-type]
    if row is None:
        row = ResourceConnection(resource_id=resource_id)
        db.add(row)

    row.protocol = body.protocol
    row.hostname = body.hostname
    row.port = body.port
    row.params_json = body.params
    row.updated_at = datetime.now(UTC)
    # Keep the policy-facing resource host/ports in sync with the guacd target.
    resource.host = body.hostname
    resource.ports = [body.port]
    # secret_params absent -> keep existing; empty dict -> clear; non-empty -> reseal.
    if body.secret_params is not None:
        if body.secret_params:
            backend = secrets.get_secrets_backend()
            key_id, blob, keys = seal_secret_params(backend, body.secret_params)
            row.key_id, row.secret_ciphertext, row.secret_keys = key_id, blob, keys
        else:
            row.key_id, row.secret_ciphertext, row.secret_keys = None, None, []
    await db.flush()

    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="resource_connection",
        entity_id=row.id,
        action="create" if creating else "update",
        before=before,
        after=_snapshot(row),
    )
    return _out(row)


@router.delete("/{resource_id}/connection", status_code=204)
async def delete_connection(resource_id: uuid.UUID, db: DbDep, authed: StepUpDep) -> None:
    row = await _load(db, resource_id)
    if row is None:
        raise HTTPException(status_code=404, detail="no connection configured")
    before = _snapshot(row)
    conn_id = row.id
    await db.delete(row)
    await db.flush()
    await record_change(
        db,
        actor_id=authed.user.id,
        entity_type="resource_connection",
        entity_id=conn_id,
        action="delete",
        before=before,
    )

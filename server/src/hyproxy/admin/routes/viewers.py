"""Read-only viewers over the audit and change-history tables.

Admin-tier reads (AdminDep, no step-up): data-plane access decisions
(audit_log), authentication events (auth_events), and admin mutations
(policy_changes). Keyset pagination on the monotonic BigInteger `id` (desc), so
paging is stable under concurrent inserts. Every response projects explicit
fields via the *Out schemas; the ORM row is never returned directly.
"""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select

from hyproxy.admin.deps import AdminDep, DbDep
from hyproxy.admin.schemas import (
    AuditAccessOut,
    AuthEventOut,
    Page,
    PolicyChangeOut,
)
from hyproxy.db.models import AuditLog, AuthEvent, PolicyChange, User

router = APIRouter(prefix="/api/v1", tags=["viewers"])

Limit = Annotated[int, Query(ge=1, le=200)]


@router.get("/audit/access")
async def list_access_audit(
    db: DbDep,
    _authed: AdminDep,
    cursor: int | None = None,
    limit: Limit = 50,
    user_id: uuid.UUID | None = None,
    resource_id: uuid.UUID | None = None,
    decision: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Page[AuditAccessOut]:
    stmt = select(AuditLog)
    if user_id is not None:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if resource_id is not None:
        stmt = stmt.where(AuditLog.resource_id == resource_id)
    if decision is not None:
        stmt = stmt.where(AuditLog.decision == decision)
    if since is not None:
        stmt = stmt.where(AuditLog.ts >= since)
    if until is not None:
        stmt = stmt.where(AuditLog.ts < until)
    if cursor is not None:
        stmt = stmt.where(AuditLog.id < cursor)
    stmt = stmt.order_by(AuditLog.id.desc()).limit(limit + 1)

    rows = list((await db.scalars(stmt)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return Page(
        items=[AuditAccessOut.model_validate(r) for r in rows],
        next_cursor=rows[-1].id if has_more and rows else None,
    )


@router.get("/audit/auth")
async def list_auth_events(
    db: DbDep,
    _authed: AdminDep,
    cursor: int | None = None,
    limit: Limit = 50,
    user_id: uuid.UUID | None = None,
    event_type: str | None = None,
    success: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Page[AuthEventOut]:
    stmt = select(AuthEvent)
    if user_id is not None:
        stmt = stmt.where(AuthEvent.user_id == user_id)
    if event_type is not None:
        stmt = stmt.where(AuthEvent.event_type == event_type)
    if success is not None:
        stmt = stmt.where(AuthEvent.success == success)
    if since is not None:
        stmt = stmt.where(AuthEvent.ts >= since)
    if until is not None:
        stmt = stmt.where(AuthEvent.ts < until)
    if cursor is not None:
        stmt = stmt.where(AuthEvent.id < cursor)
    stmt = stmt.order_by(AuthEvent.id.desc()).limit(limit + 1)

    rows = list((await db.scalars(stmt)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return Page(
        items=[AuthEventOut.model_validate(r) for r in rows],
        next_cursor=rows[-1].id if has_more and rows else None,
    )


@router.get("/policy-changes")
async def list_policy_changes(
    db: DbDep,
    _authed: AdminDep,
    cursor: int | None = None,
    limit: Limit = 50,
    actor_id: uuid.UUID | None = None,
    entity_type: str | None = None,
    entity_id: uuid.UUID | None = None,
) -> Page[PolicyChangeOut]:
    stmt = select(PolicyChange, User.email).join(User, PolicyChange.actor_id == User.id)
    if actor_id is not None:
        stmt = stmt.where(PolicyChange.actor_id == actor_id)
    if entity_type is not None:
        stmt = stmt.where(PolicyChange.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(PolicyChange.entity_id == entity_id)
    if cursor is not None:
        stmt = stmt.where(PolicyChange.id < cursor)
    stmt = stmt.order_by(PolicyChange.id.desc()).limit(limit + 1)

    rows = list((await db.execute(stmt)).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = [
        PolicyChangeOut(
            id=change.id,
            ts=change.ts,
            actor_id=change.actor_id,
            actor_email=email,
            entity_type=change.entity_type,
            entity_id=change.entity_id,
            action=change.action,
            change_json=change.change_json,
        )
        for change, email in rows
    ]
    return Page(
        items=items,
        next_cursor=rows[-1][0].id if has_more and rows else None,
    )

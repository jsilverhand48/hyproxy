"""Shared access-decision gather: turn a (user, resource, port, path) into a
policy-engine verdict plus the user's role names. Used by both the data-plane
ext-authz check and the Guacamole broker so there is one decision path."""

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import Policy, Role, UserRole
from hyproxy.policy import engine


@dataclass(frozen=True)
class AccessDecision:
    decision: engine.Decision
    role_names: list[str]


async def evaluate_access(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    resource_id: uuid.UUID,
    port: int,
    path: str,
    now: datetime,
) -> AccessDecision:
    role_rows = (
        await db.execute(
            select(Role.id, Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
        )
    ).all()
    role_ids = frozenset(row[0] for row in role_rows)
    role_names = sorted(row[1] for row in role_rows)

    policy_rows = (await db.scalars(select(Policy).where(Policy.resource_id == resource_id))).all()
    rules = [
        engine.PolicyRule(
            role_id=p.role_id,
            resource_id=p.resource_id,
            action=p.action,
            allowed_ports=tuple(p.allowed_ports) if p.allowed_ports is not None else None,
            allowed_paths=tuple(p.allowed_paths) if p.allowed_paths is not None else None,
            conditions=p.conditions_json,
            enabled=p.enabled,
        )
        for p in policy_rows
    ]
    decision = engine.evaluate(
        rules,
        user_role_ids=role_ids,
        resource_id=resource_id,
        port=port,
        path=path,
        now=now,
    )
    return AccessDecision(decision=decision, role_names=role_names)

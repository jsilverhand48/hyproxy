"""policy_changes writer: every admin mutation records actor + before/after."""

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import PolicyChange


async def record_change(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID,
    entity_type: str,
    entity_id: uuid.UUID | None,
    action: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> None:
    db.add(
        PolicyChange(
            actor_id=actor_id,
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            change_json={"before": before, "after": after},
        )
    )
    await db.flush()

"""Off-box shipping advances per-stream cursors, ships only new rows, and counts
high-severity events."""

from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import create_user
from hyproxy.audit.shipping import ship
from hyproxy.db.models import AuditLog, AuthEvent, PolicyChange

pytestmark = pytest.mark.integration


class CaptureSink:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    async def emit(self, records: Any) -> None:
        self.records.extend(records)


async def test_ships_new_rows_then_stops(
    db: AsyncSession, make_password_hash: Any
) -> None:
    admin = await create_user(db, make_password_hash, tier="admin", password="pw-ship")
    db.add_all(
        [
            AuthEvent(event_type="login.password.success", source_ip="10.0.0.1", success=True),
            AuthEvent(event_type="login.break_glass.used", source_ip="10.0.0.1", success=True),
            AuditLog(decision="deny", reason="unknown_resource", source_ip="10.0.0.2"),
            PolicyChange(
                actor_id=admin.id, entity_type="role", entity_id=None, action="create",
                change_json={"after": {"name": "x"}},
            ),
        ]
    )
    await db.flush()

    sink = CaptureSink()
    result = await ship(db, sink, batch_size=500)
    assert result.shipped["auth_events"] == 2
    assert result.shipped["audit_log"] == 1
    assert result.shipped["policy_changes"] == 1
    assert result.total == 4
    # break_glass (auth) + deny (audit) are high-severity.
    assert result.high_severity == 2
    assert len(sink.records) == 4

    # Nothing new: a second run ships zero.
    again = await ship(db, sink, batch_size=500)
    assert again.total == 0
    assert len(sink.records) == 4

    # A new row ships on the next run, and only that one.
    db.add(AuthEvent(event_type="oidc.token.issued", source_ip="10.0.0.1", success=True))
    await db.flush()
    third = await ship(db, sink, batch_size=500)
    assert third.shipped["auth_events"] == 1 and third.total == 1
    assert sink.records[-1]["event_type"] == "oidc.token.issued"


async def test_batch_size_limits_per_run(db: AsyncSession) -> None:
    for i in range(5):
        db.add(AuditLog(decision="allow", reason=f"r{i}", source_ip="10.0.0.9"))
    await db.flush()

    sink = CaptureSink()
    first = await ship(db, sink, batch_size=2)
    assert first.shipped["audit_log"] == 2
    second = await ship(db, sink, batch_size=2)
    assert second.shipped["audit_log"] == 2
    third = await ship(db, sink, batch_size=2)
    assert third.shipped["audit_log"] == 1
    # Cursor is monotonic: ids strictly increase across batches.
    ids = [r["id"] for r in sink.records if r["stream"] == "audit_log"]
    assert ids == sorted(ids) and len(set(ids)) == 5

"""Off-box audit log shipping (Phase 5).

Streams the three audit tables (auth_events, audit_log, policy_changes) to an
external, append-only collector past a per-stream high-water cursor, and flags
high-severity events for alerting. The tables are whitelist-detail by
construction (Phase 1/2), so shipped records carry no secrets. Records are
projected explicitly here; the ORM row is never emitted.

Concurrency note (reviewer item): the cursor advances by max BigInteger id per
batch. Because ids are assigned before commit, a row with a smaller id committing
after a larger one could be skipped. Acceptable for at-least-once export; a
strict pipeline should ship with a small time-lag window. Documented in
docs/security-notes.md (Phase 5).
"""

import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, TextIO

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.audit.events import AuthEventType
from hyproxy.db.models import AuditLog, AuthEvent, LogShipCursor, PolicyChange

# Events an off-box SIEM should alert on immediately.
HIGH_SEVERITY: frozenset[str] = frozenset(
    {
        AuthEventType.LOGIN_BREAK_GLASS_USED,
        AuthEventType.OIDC_CODE_REPLAY_DETECTED,
        AuthEventType.OIDC_REFRESH_REUSE_DETECTED,
        AuthEventType.SESSION_STALE_IP,
        AuthEventType.STEPUP_FAILURE,
        AuthEventType.ADMIN_TOTP_RESET,
    }
)


def is_high_severity(event_type: str) -> bool:
    return event_type in HIGH_SEVERITY


class LogSink(Protocol):
    async def emit(self, records: Sequence[dict[str, Any]]) -> None: ...


class JsonLinesSink:
    """One JSON object per record to a text stream (default stdout). The
    shippable dev default; production wires a syslog/OTLP sink to a host the
    proxy cannot delete from (append-only), keeping stdout pipeable to it."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    async def emit(self, records: Sequence[dict[str, Any]]) -> None:
        for rec in records:
            self._stream.write(json.dumps(rec, separators=(",", ":"), default=str) + "\n")
        self._stream.flush()


def _fmt_auth_event(row: AuthEvent) -> dict[str, Any]:
    return {
        "stream": "auth_events",
        "id": row.id,
        "ts": row.ts.isoformat(),
        "event_type": row.event_type,
        "user_id": str(row.user_id) if row.user_id else None,
        "session_id": str(row.session_id) if row.session_id else None,
        "client_id": row.client_id,
        "source_ip": str(row.source_ip),
        "success": row.success,
        "detail": row.detail,
        "severity": "high" if is_high_severity(row.event_type) else "normal",
    }


def _fmt_audit_log(row: AuditLog) -> dict[str, Any]:
    return {
        "stream": "audit_log",
        "id": row.id,
        "ts": row.ts.isoformat(),
        "user_id": str(row.user_id) if row.user_id else None,
        "resource_id": str(row.resource_id) if row.resource_id else None,
        "port": row.port,
        "decision": row.decision,
        "reason": row.reason,
        "source_ip": str(row.source_ip),
        "severity": "high" if row.decision == "deny" else "normal",
    }


def _fmt_policy_change(row: PolicyChange) -> dict[str, Any]:
    return {
        "stream": "policy_changes",
        "id": row.id,
        "ts": row.ts.isoformat(),
        "actor_id": str(row.actor_id),
        "entity_type": row.entity_type,
        "entity_id": str(row.entity_id) if row.entity_id else None,
        "action": row.action,
        "change": row.change_json,
        "severity": "normal",
    }


_STREAMS: list[tuple[str, Any, Any]] = [
    ("auth_events", AuthEvent, _fmt_auth_event),
    ("audit_log", AuditLog, _fmt_audit_log),
    ("policy_changes", PolicyChange, _fmt_policy_change),
]


@dataclass(frozen=True)
class ShipResult:
    shipped: dict[str, int]
    high_severity: int

    @property
    def total(self) -> int:
        return sum(self.shipped.values())


async def _cursor(db: AsyncSession, stream: str) -> int:
    row = await db.get(LogShipCursor, stream)
    return row.last_id if row else 0


async def _advance(db: AsyncSession, stream: str, last_id: int) -> None:
    row = await db.get(LogShipCursor, stream)
    if row is None:
        db.add(LogShipCursor(stream=stream, last_id=last_id))
    else:
        row.last_id = last_id
        row.updated_at = datetime.now(UTC)
    await db.flush()


async def ship(db: AsyncSession, sink: LogSink, *, batch_size: int = 500) -> ShipResult:
    """Ship one batch per stream past its cursor. The cursor advances only after
    the sink accepts the batch, so a sink failure re-ships (at-least-once)."""
    shipped: dict[str, int] = {}
    high = 0
    for stream, model, fmt in _STREAMS:
        cursor = await _cursor(db, stream)
        rows: Sequence[Any] = (
            await db.scalars(
                select(model).where(model.id > cursor).order_by(model.id).limit(batch_size)
            )
        ).all()
        if not rows:
            shipped[stream] = 0
            continue
        records = [fmt(r) for r in rows]
        await sink.emit(records)
        high += sum(1 for rec in records if rec["severity"] == "high")
        await _advance(db, stream, rows[-1].id)
        shipped[stream] = len(records)
    return ShipResult(shipped=shipped, high_severity=high)

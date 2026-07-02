"""Transport-agnostic policy decision core (spec section 5).

Pure functions over plain dataclasses so the engine can be property-tested
without a database and reused by any transport (HTTP forward-auth today, the
raw-L4 listener later).

Decision order, per spec: among the rules that APPLY to the request
(enabled, same resource, role held by the user, and every condition
matching), an explicit deny wins over any allow; with no applicable allow,
the default is deny.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from typing import Any

DAY_KEYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


@dataclass(frozen=True)
class PolicyRule:
    role_id: uuid.UUID
    resource_id: uuid.UUID
    action: str  # "allow" | "deny"
    allowed_ports: tuple[int, ...] | None = None
    allowed_paths: tuple[str, ...] | None = None
    conditions: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _parse_hhmm(value: str) -> time | None:
    try:
        parsed = datetime.strptime(value, "%H:%M")
    except (TypeError, ValueError):
        return None
    return parsed.time()


def time_window_matches(conditions: dict[str, Any], now: datetime) -> bool:
    """conditions["time_windows"]: list of {days: ["mon",...], start: "HH:MM",
    end: "HH:MM"} evaluated in UTC. No windows means always. A malformed
    window never matches (fail closed for that window)."""
    windows = conditions.get("time_windows")
    if not windows:
        return True
    if not isinstance(windows, list):
        return False
    now_utc = now.astimezone(UTC)
    day_key = DAY_KEYS[now_utc.weekday()]
    current = now_utc.time().replace(second=0, microsecond=0)
    for window in windows:
        if not isinstance(window, dict):
            continue
        days = window.get("days")
        if days is not None and (not isinstance(days, list) or day_key not in days):
            continue
        start = _parse_hhmm(window.get("start", "00:00"))
        end = _parse_hhmm(window.get("end", "23:59"))
        if start is None or end is None:
            continue
        if start <= end:
            if start <= current <= end:
                return True
        else:  # crosses midnight, e.g. 22:00..06:00
            if current >= start or current <= end:
                return True
    return False


def rule_applies(
    rule: PolicyRule,
    *,
    user_role_ids: frozenset[uuid.UUID],
    resource_id: uuid.UUID,
    port: int,
    path: str,
    now: datetime,
) -> bool:
    if not rule.enabled:
        return False
    if rule.resource_id != resource_id:
        return False
    if rule.role_id not in user_role_ids:
        return False
    if rule.allowed_ports is not None and port not in rule.allowed_ports:
        return False
    if rule.allowed_paths is not None and not any(
        path == prefix or path.startswith(prefix.rstrip("/") + "/") or prefix == "/"
        for prefix in rule.allowed_paths
    ):
        return False
    return time_window_matches(rule.conditions, now)


def evaluate(
    rules: list[PolicyRule],
    *,
    user_role_ids: frozenset[uuid.UUID],
    resource_id: uuid.UUID,
    port: int,
    path: str,
    now: datetime,
) -> Decision:
    applicable = [
        r
        for r in rules
        if rule_applies(
            r,
            user_role_ids=user_role_ids,
            resource_id=resource_id,
            port=port,
            path=path,
            now=now,
        )
    ]
    if any(r.action == "deny" for r in applicable):
        return Decision(allowed=False, reason="explicit_deny")
    if any(r.action == "allow" for r in applicable):
        return Decision(allowed=True, reason="allow")
    return Decision(allowed=False, reason="default_deny")

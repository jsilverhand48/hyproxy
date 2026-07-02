"""Progressive-delay rate limiting backed by the auth_throttle table.

No hard lockout: delays cap (60s account, 30s IP) so a legitimate user is
never permanently locked out, while credential stuffing is throttled. The
check runs BEFORE credential evaluation, which also bounds argon2 CPU spend
under attack.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.db.models import AuthThrottle


@dataclass(frozen=True)
class ThrottleDecision:
    allowed: bool
    retry_after: int = 0  # seconds, for the Retry-After header


def delay_seconds(scope: str, failure_count: int) -> int:
    s = get_settings()
    if scope == "account":
        free, cap = s.throttle_account_free_failures, s.throttle_account_max_delay
    else:
        free, cap = s.throttle_ip_free_failures, s.throttle_ip_max_delay
    if failure_count <= free:
        return 0
    return min(1 << (failure_count - free), cap)


async def check(
    session: AsyncSession, *, source_ip: str, account_key: str | None, now: datetime
) -> ThrottleDecision:
    """Deny if either the IP or the account is inside its delay window."""
    keys = [("ip", source_ip)]
    if account_key is not None:
        keys.append(("account", account_key))
    worst = ThrottleDecision(allowed=True)
    for scope, key in keys:
        row = await session.scalar(
            select(AuthThrottle).where(AuthThrottle.scope == scope, AuthThrottle.key == key)
        )
        if row is not None and row.next_allowed_at > now:
            retry = int((row.next_allowed_at - now).total_seconds()) + 1
            if retry > worst.retry_after:
                worst = ThrottleDecision(allowed=False, retry_after=retry)
    return worst


async def register_failure(
    session: AsyncSession, *, source_ip: str, account_key: str | None, now: datetime
) -> None:
    """Record a failed attempt on both scopes, with window reset and row locking."""
    window = timedelta(seconds=get_settings().throttle_window)
    keys = [("ip", source_ip)]
    if account_key is not None:
        keys.append(("account", account_key))
    for scope, key in keys:
        # Upsert so concurrent first-failures don't race, then lock and update.
        await session.execute(
            pg_insert(AuthThrottle)
            .values(
                scope=scope, key=key, failure_count=0, window_started_at=now, next_allowed_at=now
            )
            .on_conflict_do_nothing(index_elements=["scope", "key"])
        )
        row = await session.scalar(
            select(AuthThrottle)
            .where(AuthThrottle.scope == scope, AuthThrottle.key == key)
            .with_for_update()
        )
        assert row is not None
        if now - row.window_started_at > window:
            row.failure_count = 0
            row.window_started_at = now
        row.failure_count += 1
        row.next_allowed_at = now + timedelta(seconds=delay_seconds(scope, row.failure_count))
    await session.flush()


async def reset_account(session: AsyncSession, account_key: str) -> None:
    """On successful login, clear the account-scope counter (IP scope decays alone)."""
    await session.execute(
        delete(AuthThrottle).where(AuthThrottle.scope == "account", AuthThrottle.key == account_key)
    )

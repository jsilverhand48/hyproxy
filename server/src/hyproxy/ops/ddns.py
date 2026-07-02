"""DDNS decision core.

Keeps the public DNS record current for the home IP. The decision (whether to
update) is a pure function; the provider API and public-IP lookup are isolated
behind small interfaces so this module carries no provider-specific code and is
fully testable. Idempotent (no update when unchanged) and rate-limited (a
minimum interval between set attempts) to avoid update storms.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol


class DnsProvider(Protocol):
    async def get_record(self, hostname: str) -> str | None: ...

    async def set_record(self, hostname: str, ip: str) -> None: ...


@dataclass(frozen=True)
class UpdateDecision:
    update: bool
    reason: str  # "changed" | "unchanged" | "no_current_ip" | "backoff"


@dataclass
class DdnsState:
    last_attempt: datetime | None = None


def decide(
    current_ip: str | None,
    record_ip: str | None,
    last_attempt: datetime | None,
    now: datetime,
    *,
    min_interval: timedelta,
) -> UpdateDecision:
    if not current_ip:
        return UpdateDecision(False, "no_current_ip")
    if last_attempt is not None and now - last_attempt < min_interval:
        return UpdateDecision(False, "backoff")
    if current_ip == record_ip:
        return UpdateDecision(False, "unchanged")
    return UpdateDecision(True, "changed")


async def update_if_needed(
    provider: DnsProvider,
    hostname: str,
    current_ip: str | None,
    *,
    now: datetime,
    min_interval: timedelta,
    state: DdnsState,
) -> UpdateDecision:
    """Fetch the current record, decide, and set it only when it changed and the
    backoff window has elapsed. Records the attempt time so repeated failures
    back off instead of storming the provider."""
    record = await provider.get_record(hostname)
    decision = decide(current_ip, record, state.last_attempt, now, min_interval=min_interval)
    if decision.update:
        state.last_attempt = now
        assert current_ip is not None
        await provider.set_record(hostname, current_ip)
    return decision

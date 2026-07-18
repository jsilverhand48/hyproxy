"""DDNS decision core: idempotent, backoff-limited, provider-agnostic."""

from datetime import UTC, datetime, timedelta

from hyproxy.ops.ddns import DdnsState, decide, update_if_needed

NOW = datetime(2026, 7, 2, 12, 0, tzinfo=UTC)
MIN = timedelta(minutes=5)


def test_decide_cases() -> None:
    assert decide("1.2.3.4", "9.9.9.9", None, NOW, min_interval=MIN).reason == "changed"
    assert decide("1.2.3.4", "1.2.3.4", None, NOW, min_interval=MIN).reason == "unchanged"
    assert decide(None, "1.2.3.4", None, NOW, min_interval=MIN).reason == "no_current_ip"
    recent = NOW - timedelta(minutes=1)
    assert decide("1.2.3.4", "9.9.9.9", recent, NOW, min_interval=MIN).reason == "backoff"
    old = NOW - timedelta(minutes=10)
    assert decide("1.2.3.4", "9.9.9.9", old, NOW, min_interval=MIN).update is True


class FakeProvider:
    def __init__(self, record: str | None) -> None:
        self.record = record
        self.sets: list[tuple[str, str]] = []

    async def get_record(self, hostname: str) -> str | None:
        return self.record

    async def set_record(self, hostname: str, ip: str) -> None:
        self.sets.append((hostname, ip))
        self.record = ip


async def test_update_sets_only_when_changed() -> None:
    provider = FakeProvider(record="9.9.9.9")
    state = DdnsState()
    d = await update_if_needed(
        provider, "home.example.com", "1.2.3.4", now=NOW, min_interval=MIN, state=state
    )
    assert d.update and provider.sets == [("home.example.com", "1.2.3.4")]
    assert state.last_attempt == NOW

    # Same IP now: no further set.
    d2 = await update_if_needed(
        provider, "home.example.com", "1.2.3.4",
        now=NOW + timedelta(minutes=10), min_interval=MIN, state=state,
    )
    assert not d2.update and len(provider.sets) == 1


async def test_backoff_prevents_storm() -> None:
    provider = FakeProvider(record="9.9.9.9")
    state = DdnsState(last_attempt=NOW - timedelta(minutes=1))
    d = await update_if_needed(
        provider, "home.example.com", "1.2.3.4", now=NOW, min_interval=MIN, state=state
    )
    assert not d.update and d.reason == "backoff" and provider.sets == []

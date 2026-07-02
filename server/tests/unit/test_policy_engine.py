import uuid
from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from hyproxy.policy.engine import (
    Decision,
    PolicyRule,
    evaluate,
    rule_applies,
    time_window_matches,
)

NOW = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)  # a Wednesday
RESOURCE = uuid.uuid4()
OTHER_RESOURCE = uuid.uuid4()
ROLE_A = uuid.uuid4()
ROLE_B = uuid.uuid4()


def ev(rules: list[PolicyRule], *, roles: frozenset[uuid.UUID] | None = None, port: int = 443,
       path: str = "/", now: datetime = NOW) -> Decision:
    return evaluate(
        rules,
        user_role_ids=roles if roles is not None else frozenset({ROLE_A}),
        resource_id=RESOURCE,
        port=port,
        path=path,
        now=now,
    )


def allow(**kw: object) -> PolicyRule:
    defaults: dict[str, object] = {"role_id": ROLE_A, "resource_id": RESOURCE, "action": "allow"}
    defaults.update(kw)
    return PolicyRule(**defaults)  # type: ignore[arg-type]


def deny(**kw: object) -> PolicyRule:
    return allow(action="deny", **kw)  # type: ignore[arg-type]


# --- example-based ------------------------------------------------------------


def test_default_deny_with_no_rules() -> None:
    d = ev([])
    assert not d.allowed and d.reason == "default_deny"


def test_simple_allow() -> None:
    assert ev([allow()]).allowed


def test_explicit_deny_beats_allow() -> None:
    d = ev([allow(), deny()])
    assert not d.allowed and d.reason == "explicit_deny"


def test_rule_for_other_resource_ignored() -> None:
    assert not ev([allow(resource_id=OTHER_RESOURCE)]).allowed


def test_rule_for_unheld_role_ignored() -> None:
    assert not ev([allow(role_id=ROLE_B)]).allowed
    assert ev([allow(role_id=ROLE_B)], roles=frozenset({ROLE_A, ROLE_B})).allowed


def test_disabled_rules_are_inert() -> None:
    assert not ev([allow(enabled=False)]).allowed
    assert ev([allow(), deny(enabled=False)]).allowed


def test_port_gating() -> None:
    rule = allow(allowed_ports=(8080, 8443))
    assert ev([rule], port=8080).allowed
    assert not ev([rule], port=9000).allowed


def test_path_prefix_gating() -> None:
    rule = allow(allowed_paths=("/web",))
    assert ev([rule], path="/web").allowed
    assert ev([rule], path="/web/photos").allowed
    assert not ev([rule], path="/webby").allowed  # prefix is segment-aware
    assert not ev([rule], path="/admin").allowed


def test_scoped_deny_only_applies_where_it_matches() -> None:
    rules = [allow(), deny(allowed_paths=("/admin",))]
    assert ev(rules, path="/photos").allowed
    assert not ev(rules, path="/admin/settings").allowed


def test_time_window_inside_and_outside() -> None:
    windowed = allow(conditions={"time_windows": [{"days": ["wed"], "start": "08:00", "end": "17:00"}]})
    assert ev([windowed]).allowed  # Wednesday noon
    late = NOW.replace(hour=23)
    assert not ev([windowed], now=late).allowed
    thursday = datetime(2026, 7, 2, 12, 0, tzinfo=UTC)
    assert not ev([windowed], now=thursday).allowed


def test_time_window_crossing_midnight() -> None:
    conditions = {"time_windows": [{"start": "22:00", "end": "06:00"}]}
    assert time_window_matches(conditions, NOW.replace(hour=23))
    assert time_window_matches(conditions, NOW.replace(hour=5))
    assert not time_window_matches(conditions, NOW.replace(hour=12))


def test_malformed_time_window_fails_closed() -> None:
    assert not time_window_matches({"time_windows": [{"start": "25:99", "end": "xx"}]}, NOW)
    assert not time_window_matches({"time_windows": "notalist"}, NOW)
    # But an absent/empty windows key means "always".
    assert time_window_matches({}, NOW)


# --- property-based -----------------------------------------------------------

role_ids = st.sampled_from([ROLE_A, ROLE_B])
actions = st.sampled_from(["allow", "deny"])
ports_opt = st.one_of(st.none(), st.tuples(st.integers(1, 65535)))
paths_opt = st.one_of(st.none(), st.tuples(st.sampled_from(["/", "/a", "/a/b", "/c"])))

rules_strategy = st.lists(
    st.builds(
        PolicyRule,
        role_id=role_ids,
        resource_id=st.sampled_from([RESOURCE, OTHER_RESOURCE]),
        action=actions,
        allowed_ports=ports_opt,
        allowed_paths=paths_opt,
        conditions=st.just({}),
        enabled=st.booleans(),
    ),
    max_size=12,
)

request_ports = st.integers(1, 65535)
request_paths = st.sampled_from(["/", "/a", "/a/b", "/a/b/c", "/c", "/d"])
role_sets = st.frozensets(role_ids, max_size=2)


@given(rules=rules_strategy, port=request_ports, path=request_paths, roles=role_sets)
def test_property_deny_never_overridden(
    rules: list[PolicyRule], port: int, path: str, roles: frozenset[uuid.UUID]
) -> None:
    decision = evaluate(
        rules, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW
    )
    applicable = [
        r
        for r in rules
        if rule_applies(
            r, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW
        )
    ]
    if any(r.action == "deny" for r in applicable):
        assert not decision.allowed and decision.reason == "explicit_deny"


@given(rules=rules_strategy, port=request_ports, path=request_paths, roles=role_sets)
def test_property_allow_requires_applicable_allow_and_no_deny(
    rules: list[PolicyRule], port: int, path: str, roles: frozenset[uuid.UUID]
) -> None:
    decision = evaluate(
        rules, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW
    )
    applicable = [
        r
        for r in rules
        if rule_applies(
            r, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW
        )
    ]
    has_allow = any(r.action == "allow" for r in applicable)
    has_deny = any(r.action == "deny" for r in applicable)
    assert decision.allowed == (has_allow and not has_deny)


@given(rules=rules_strategy, port=request_ports, path=request_paths, roles=role_sets)
def test_property_default_deny_when_nothing_applies(
    rules: list[PolicyRule], port: int, path: str, roles: frozenset[uuid.UUID]
) -> None:
    stripped = [
        r
        for r in rules
        if not rule_applies(
            r, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW
        )
    ]
    decision = evaluate(
        stripped, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW
    )
    assert not decision.allowed and decision.reason == "default_deny"


@given(rules=rules_strategy, port=request_ports, path=request_paths, roles=role_sets)
def test_property_disabled_rules_never_change_outcome(
    rules: list[PolicyRule], port: int, path: str, roles: frozenset[uuid.UUID]
) -> None:
    enabled_only = [r for r in rules if r.enabled]
    a = evaluate(rules, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW)
    b = evaluate(
        enabled_only, user_role_ids=roles, resource_id=RESOURCE, port=port, path=path, now=NOW
    )
    assert a == b

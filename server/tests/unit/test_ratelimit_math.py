from hyproxy.security.ratelimit import delay_seconds


def test_account_scope_free_failures_then_exponential() -> None:
    assert [delay_seconds("account", f) for f in range(1, 4)] == [0, 0, 0]
    assert delay_seconds("account", 4) == 2
    assert delay_seconds("account", 5) == 4
    assert delay_seconds("account", 6) == 8
    assert delay_seconds("account", 9) == 60  # capped
    assert delay_seconds("account", 50) == 60


def test_ip_scope_is_coarser_for_nat() -> None:
    assert all(delay_seconds("ip", f) == 0 for f in range(1, 11))
    assert delay_seconds("ip", 11) == 2
    assert delay_seconds("ip", 14) == 16
    assert delay_seconds("ip", 15) == 30  # capped
    assert delay_seconds("ip", 100) == 30

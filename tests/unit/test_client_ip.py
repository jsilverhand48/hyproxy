"""resolve_client_ip: socket peer vs trusted X-Forwarded-For."""

from types import SimpleNamespace

import pytest

from hyproxy.config import get_settings
from hyproxy.core.netutil import resolve_client_ip


def _request(*, peer: str, xff: str | None):
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers)


@pytest.fixture(autouse=True)
def _reset_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_uses_socket_peer_when_not_trusting(monkeypatch):
    monkeypatch.setenv("HYPROXY_TRUST_FORWARDED_FOR", "false")
    get_settings.cache_clear()
    req = _request(peer="10.0.0.1", xff="203.0.113.5")
    assert resolve_client_ip(req) == "10.0.0.1"


def test_uses_leftmost_forwarded_when_trusting(monkeypatch):
    monkeypatch.setenv("HYPROXY_TRUST_FORWARDED_FOR", "true")
    get_settings.cache_clear()
    req = _request(peer="10.0.0.1", xff="203.0.113.5, 10.0.0.1")
    assert resolve_client_ip(req) == "203.0.113.5"


def test_falls_back_to_peer_when_trusting_but_no_header(monkeypatch):
    monkeypatch.setenv("HYPROXY_TRUST_FORWARDED_FOR", "true")
    get_settings.cache_clear()
    req = _request(peer="10.0.0.1", xff=None)
    assert resolve_client_ip(req) == "10.0.0.1"

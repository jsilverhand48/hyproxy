"""Open-redirect defense for the step-up return target: it must equal the
configured admin-UI origin exactly, or nothing is accepted."""

import pytest

from hyproxy.config import get_settings
from hyproxy.idp.web.webauthn_routes import valid_stepup_return


@pytest.fixture
def admin_origin(monkeypatch: pytest.MonkeyPatch) -> str:
    origin = "https://admin-ui.test"
    monkeypatch.setattr(get_settings(), "admin_ui_origin", origin)
    return origin


def test_accepts_paths_on_the_configured_origin(admin_origin: str) -> None:
    assert valid_stepup_return("https://admin-ui.test/")
    assert valid_stepup_return("https://admin-ui.test/users?tab=roles")


def test_rejects_other_hosts_and_smuggling(admin_origin: str) -> None:
    assert not valid_stepup_return("https://evil.test/")
    assert not valid_stepup_return("https://admin-ui.test.evil.test/")
    assert not valid_stepup_return("https://admin-ui.test@evil.test/")  # userinfo trick
    assert not valid_stepup_return("http://admin-ui.test/")  # scheme must match origin
    assert not valid_stepup_return("javascript:alert(1)")
    assert not valid_stepup_return("//admin-ui.test/")
    assert not valid_stepup_return("")


def test_disabled_when_no_admin_ui_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "admin_ui_origin", "")
    assert not valid_stepup_return("https://admin-ui.test/")

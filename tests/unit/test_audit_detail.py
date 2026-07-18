import pytest

from hyproxy.audit.events import ALLOWED_DETAIL_KEYS, _validate_detail


def test_allowed_keys_pass() -> None:
    _validate_detail({"reason": "expired", "retry_after": 30})


def test_secret_bearing_keys_rejected() -> None:
    for key in ("password", "totp_code", "refresh_token", "code_verifier", "secret"):
        with pytest.raises(ValueError, match="disallowed"):
            _validate_detail({key: "x"})


def test_long_values_rejected() -> None:
    with pytest.raises(ValueError, match="short scalar"):
        _validate_detail({"reason": "x" * 300})


def test_non_scalar_values_rejected() -> None:
    with pytest.raises(ValueError, match="short scalar"):
        _validate_detail({"reason": {"nested": "dict"}})


def test_whitelist_has_no_secret_looking_keys() -> None:
    banned_substrings = ("password", "token", "secret", "verifier", "assertion")
    for key in ALLOWED_DETAIL_KEYS:
        assert not any(b in key for b in banned_substrings), key

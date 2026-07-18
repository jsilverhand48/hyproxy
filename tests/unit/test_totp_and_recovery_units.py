from datetime import UTC, datetime, timedelta

import pyotp

from hyproxy.security import totp as totp_service
from hyproxy.security.recovery import ALPHABET, _generate_code, normalize


def test_totp_verify_current_code() -> None:
    secret = totp_service.generate_secret()
    now = datetime.now(UTC)
    code = pyotp.TOTP(secret).at(now)
    assert totp_service.verify_code(secret, code, at=now)


def test_totp_rejects_wrong_code() -> None:
    secret = totp_service.generate_secret()
    now = datetime.now(UTC)
    good = pyotp.TOTP(secret).at(now)
    bad = f"{(int(good) + 1) % 1000000:06d}"
    assert not totp_service.verify_code(secret, bad, at=now)


def test_totp_drift_window_one_step() -> None:
    secret = totp_service.generate_secret()
    now = datetime.now(UTC)
    prev_code = pyotp.TOTP(secret).at(now - timedelta(seconds=30))
    old_code = pyotp.TOTP(secret).at(now - timedelta(seconds=90))
    assert totp_service.verify_code(secret, prev_code, at=now)
    assert not totp_service.verify_code(secret, old_code, at=now)


def test_recovery_code_format_and_alphabet() -> None:
    for _ in range(20):
        code = _generate_code()
        assert len(code) == 11 and code[5] == "-"
        assert all(c in ALPHABET for c in code.replace("-", ""))


def test_recovery_normalize() -> None:
    assert normalize(" ab2c3-D4ef5 ") == "AB2C3D4EF5"
    assert normalize("AB2C3D4EF5") == "AB2C3D4EF5"

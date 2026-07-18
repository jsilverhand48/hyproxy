from hyproxy.security.passwords import dummy_verify, hash_password, verify_password


def test_hash_and_verify_roundtrip() -> None:
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery staple")


def test_wrong_password_rejected() -> None:
    h = hash_password("right")
    assert not verify_password(h, "wrong")


def test_garbage_hash_rejected_without_raising() -> None:
    assert not verify_password("$argon2id$nonsense", "anything")


def test_dummy_verify_burns_cost_without_error() -> None:
    dummy_verify()  # must not raise

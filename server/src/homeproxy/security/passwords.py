"""argon2id password hashing (argon2-cffi defaults, which are argon2id)."""

from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerificationError:
        return False


@lru_cache
def _dummy_hash() -> str:
    return _hasher.hash("dummy-password-for-timing-equalization")


def dummy_verify() -> None:
    """Burn the same argon2 cost as a real verify, for unknown-user requests."""
    try:
        _hasher.verify(_dummy_hash(), "not-the-password")
    except VerificationError:
        pass


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)

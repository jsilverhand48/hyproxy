from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from hyproxy.core.crypto import (
    constant_time_equals,
    decrypt_blob,
    encrypt_blob,
    new_token,
    sha256_b64url,
    sha256_hex,
)
from hyproxy.core.secrets import (
    MASTER_KEY_BYTES,
    FileSecretsBackend,
    generate_master_key_file,
)


@pytest.fixture
def backend(tmp_path: Path) -> FileSecretsBackend:
    path = tmp_path / "master.keys"
    generate_master_key_file(path)
    return FileSecretsBackend(path)


def test_encrypt_decrypt_roundtrip(backend: FileSecretsBackend) -> None:
    key_id, blob = encrypt_blob(backend, b"attack at dawn", aad="user_totp")
    assert blob != b"attack at dawn"
    assert decrypt_blob(backend, key_id, blob, aad="user_totp") == b"attack at dawn"


def test_decrypt_rejects_wrong_aad(backend: FileSecretsBackend) -> None:
    key_id, blob = encrypt_blob(backend, b"secret", aad="user_totp")
    with pytest.raises(InvalidTag):
        decrypt_blob(backend, key_id, blob, aad="signing_keys")


def test_decrypt_rejects_tampered_ciphertext(backend: FileSecretsBackend) -> None:
    key_id, blob = encrypt_blob(backend, b"secret", aad="t")
    tampered = blob[:-1] + bytes([blob[-1] ^ 0x01])
    with pytest.raises(InvalidTag):
        decrypt_blob(backend, key_id, tampered, aad="t")


def test_unknown_master_key_id(backend: FileSecretsBackend) -> None:
    with pytest.raises(KeyError):
        backend.get_master_key("mk-999")


def test_master_key_rotation_appends_and_current_is_last(tmp_path: Path) -> None:
    path = tmp_path / "master.keys"
    first = generate_master_key_file(path)
    second = generate_master_key_file(path)
    backend = FileSecretsBackend(path)
    assert backend.current_key_id() == second
    assert first != second
    assert len(backend.get_master_key(first)) == MASTER_KEY_BYTES
    # Old-key ciphertext still decrypts after rotation.
    key_id, blob = encrypt_blob(backend, b"x", aad="a")
    assert key_id == second
    assert decrypt_blob(backend, key_id, blob, aad="a") == b"x"


def test_master_key_file_permissions(tmp_path: Path) -> None:
    path = tmp_path / "master.keys"
    generate_master_key_file(path)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_hash_helpers_are_stable() -> None:
    assert sha256_hex("abc") == sha256_hex(b"abc")
    assert sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    # RFC 7636 appendix B test vector
    assert (
        sha256_b64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_new_token_entropy_and_uniqueness() -> None:
    tokens = {new_token() for _ in range(100)}
    assert len(tokens) == 100
    assert all(len(t) >= 43 for t in tokens)


def test_constant_time_equals() -> None:
    assert constant_time_equals("abc", "abc")
    assert not constant_time_equals("abc", "abd")
    assert not constant_time_equals("abc", "ab")

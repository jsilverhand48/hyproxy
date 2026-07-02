"""Envelope encryption and hashing helpers built on vetted primitives only."""

import base64
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from hyproxy.core.secrets import SecretsBackend

NONCE_BYTES = 12


def encrypt_blob(backend: SecretsBackend, plaintext: bytes, aad: str) -> tuple[str, bytes]:
    """AES-256-GCM under the current master key. Returns (key_id, nonce || ciphertext)."""
    key_id = backend.current_key_id()
    nonce = secrets.token_bytes(NONCE_BYTES)
    ct = AESGCM(backend.get_master_key(key_id)).encrypt(nonce, plaintext, aad.encode())
    return key_id, nonce + ct


def decrypt_blob(backend: SecretsBackend, key_id: str, blob: bytes, aad: str) -> bytes:
    nonce, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:]
    return AESGCM(backend.get_master_key(key_id)).decrypt(nonce, ct, aad.encode())


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def sha256_b64url(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def new_token(nbytes: int = 32) -> str:
    """Full-entropy urlsafe random token (auth codes, refresh tokens, cookie secrets)."""
    return secrets.token_urlsafe(nbytes)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

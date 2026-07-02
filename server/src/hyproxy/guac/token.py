"""guacamole-lite token codec.

Mirrors guacamole-lite's default `Crypt` (AES-256-CBC): the connection object is
JSON-encoded, PKCS7-padded, AES-256-CBC encrypted under a shared 32-byte key
with a random IV, and wrapped as base64(JSON({"iv": b64(iv), "value": b64(ct)})).
The Node tunnel decrypts it with the same key and connects to guacd. The key is
a bearer secret to the remote resource, so tokens are short-lived and the tunnel
connect is forward-authed and single-use-consumed (data plane).
"""

import base64
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

_KEY_BYTES = 32
_BLOCK_BITS = 128


def load_cypher_key(b64_key: str) -> bytes:
    """Decode the base64 32-byte AES-256-CBC key shared with the Node tunnel."""
    key = base64.b64decode(b64_key)
    if len(key) != _KEY_BYTES:
        raise ValueError("guac cypher key must be 32 bytes (base64-encoded)")
    return key


def mint_token(key: bytes, connection: dict[str, Any]) -> str:
    if len(key) != _KEY_BYTES:
        raise ValueError("guac cypher key must be 32 bytes")
    iv = secrets.token_bytes(16)
    plaintext = json.dumps(connection, separators=(",", ":")).encode()
    padder = PKCS7(_BLOCK_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    envelope = {
        "iv": base64.b64encode(iv).decode(),
        "value": base64.b64encode(ct).decode(),
    }
    return base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode()).decode()


def decrypt_token(key: bytes, token: str) -> dict[str, Any]:
    """Inverse of mint_token (for tests and any server-side verification)."""
    envelope = json.loads(base64.b64decode(token))
    iv = base64.b64decode(envelope["iv"])
    ct = base64.b64decode(envelope["value"])
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = PKCS7(_BLOCK_BITS).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    result: dict[str, Any] = json.loads(plaintext)
    return result

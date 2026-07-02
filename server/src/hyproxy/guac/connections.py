"""Sealing of Guacamole connection secret parameters.

Secret parameters (password, private-key, passphrase, ...) are AES-256-GCM
sealed under the master key via the SecretsBackend with the table name as AAD,
exactly like TOTP secrets. Only the parameter NAMES are stored in cleartext
(`secret_keys`) so the admin UI can show which secrets are set without ever
decrypting them.
"""

import json

from hyproxy.core.crypto import decrypt_blob, encrypt_blob
from hyproxy.core.secrets import SecretsBackend
from hyproxy.db.models import ResourceConnection

_AAD = "resource_connections"


def seal_secret_params(
    backend: SecretsBackend, params: dict[str, str]
) -> tuple[str, bytes, list[str]]:
    """Returns (key_id, nonce||ciphertext, sorted key names)."""
    plaintext = json.dumps(params, separators=(",", ":")).encode()
    key_id, blob = encrypt_blob(backend, plaintext, _AAD)
    return key_id, blob, sorted(params)


def unseal_secret_params(backend: SecretsBackend, row: ResourceConnection) -> dict[str, str]:
    if row.secret_ciphertext is None or row.key_id is None:
        return {}
    raw = decrypt_blob(backend, row.key_id, row.secret_ciphertext, _AAD)
    result: dict[str, str] = json.loads(raw)
    return result

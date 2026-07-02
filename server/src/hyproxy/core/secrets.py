"""Master-key access abstraction.

Phase 1 ships a file-backed dev implementation. The Phase 5 TPM-backed secrets
broker implements the same protocol; nothing else in the codebase changes.
"""

import base64
import secrets
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from hyproxy.config import get_settings

MASTER_KEY_BYTES = 32


class SecretsBackend(Protocol):
    def current_key_id(self) -> str: ...

    def get_master_key(self, key_id: str) -> bytes: ...


def parse_master_keys(text: str) -> tuple[dict[str, bytes], str]:
    """Parse `key_id:base64key` lines; the last non-comment line is current."""
    keys: dict[str, bytes] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key_id, _, b64 = line.partition(":")
        key = base64.b64decode(b64)
        if len(key) != MASTER_KEY_BYTES:
            raise ValueError(f"master key {key_id!r} is not {MASTER_KEY_BYTES} bytes")
        keys[key_id] = key
        current = key_id
    if current is None:
        raise ValueError("no master keys found")
    return keys, current


class _MapBackend:
    """Shared key store: serves keys by id and names the current one."""

    def __init__(self, keys: dict[str, bytes], current: str) -> None:
        self._keys = keys
        self._current = current

    def current_key_id(self) -> str:
        return self._current

    def get_master_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(f"unknown master key id {key_id!r}") from None


class FileSecretsBackend(_MapBackend):
    """Reads `key_id:base64key` lines; the last line is the current key.

    Dev-only: the master key sits on disk (chmod 600). Production uses the
    TPM-backed broker below.
    """

    def __init__(self, path: Path) -> None:
        keys, current = parse_master_keys(path.read_text())
        super().__init__(keys, current)


class TpmSecretsBackend(_MapBackend):
    """Master keys unsealed from the TPM at process start into memory only.

    The unsealed payload is the SAME `key_id:base64` format as the file backend,
    but it is sealed to the TPM under a PCR policy and never touches disk in
    cleartext. The TPM interaction is isolated behind the injected `unseal`
    callable (returns the key text), so this adapter is testable without
    hardware; production wires `unseal` to `tpm2_unseal` (see `tpm_unseal`).
    """

    def __init__(self, unseal: Callable[[], str]) -> None:
        keys, current = parse_master_keys(unseal())
        super().__init__(keys, current)


def tpm_unseal() -> str:
    """Unseal the master-key blob from the TPM (production only).

    Deployment-specific: unseal `HYPROXY_TPM_SEALED_BLOB` under the configured
    PCR policy via tpm2-tools (`tpm2_unseal`) or tpm2-pytss, returning the
    `key_id:base64` text. Not implemented in-repo because it requires a TPM,
    which the dev machine lacks; wire it at deploy time.
    """
    raise NotImplementedError(
        "TPM unseal is a deployment integration point; see docs/security-notes.md "
        "(Phase 5) and provide tpm2_unseal wiring"
    )


def generate_master_key_file(path: Path) -> str:
    """Create (or append a new key to) the dev master key file. Returns the new key id."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text() if path.exists() else ""
    n = sum(1 for line in existing.splitlines() if line.strip() and not line.startswith("#"))
    key_id = f"mk-{n + 1}"
    b64 = base64.b64encode(secrets.token_bytes(MASTER_KEY_BYTES)).decode()
    with path.open("a") as f:
        f.write(f"{key_id}:{b64}\n")
    path.chmod(0o600)
    return key_id


@lru_cache
def get_secrets_backend() -> SecretsBackend:
    settings = get_settings()
    if settings.secrets_backend == "tpm":
        return TpmSecretsBackend(tpm_unseal)
    return FileSecretsBackend(Path(settings.master_key_file))

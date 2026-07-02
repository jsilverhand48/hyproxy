"""Master-key access abstraction.

Phase 1 ships a file-backed dev implementation. The Phase 5 TPM-backed secrets
broker implements the same protocol; nothing else in the codebase changes.
"""

import base64
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from hyproxy.config import get_settings

MASTER_KEY_BYTES = 32


class SecretsBackend(Protocol):
    def current_key_id(self) -> str: ...

    def get_master_key(self, key_id: str) -> bytes: ...


class FileSecretsBackend:
    """Reads `key_id:base64key` lines; the last line is the current key.

    Dev-only. Production replaces this with the TPM-backed broker (Phase 5).
    """

    def __init__(self, path: Path) -> None:
        self._keys: dict[str, bytes] = {}
        self._current: str | None = None
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key_id, _, b64 = line.partition(":")
            key = base64.b64decode(b64)
            if len(key) != MASTER_KEY_BYTES:
                raise ValueError(f"master key {key_id!r} is not {MASTER_KEY_BYTES} bytes")
            self._keys[key_id] = key
            self._current = key_id
        if self._current is None:
            raise ValueError(f"no master keys found in {path}")

    def current_key_id(self) -> str:
        assert self._current is not None
        return self._current

    def get_master_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(f"unknown master key id {key_id!r}") from None


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
    return FileSecretsBackend(Path(get_settings().master_key_file))

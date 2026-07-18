"""Master-key access abstraction.

The master key is sealed in the TPM and unsealed into process memory at
startup; there is no other backend. Any unseal failure raises and aborts
startup (fail closed).
"""

import base64
import hashlib
from collections.abc import Callable
from functools import lru_cache
from typing import Protocol

from hyproxy.config import get_settings

MASTER_KEY_BYTES = 32


def master_key_fingerprint(key: bytes) -> str:
    """Non-secret identity of a master key: first 16 hex of SHA-256(key).

    Recorded in the deployment's .env (HYPROXY_MASTER_KEY_FP) so a resealed or
    swapped blob whose bytes differ from what encrypted the database is caught
    at startup instead of surfacing as an AES-GCM InvalidTag at request time.
    Colliding key ids (two different `mk-1` keys) share a label but never a
    fingerprint, so this distinguishes them where the id alone cannot.
    """
    return hashlib.sha256(key).hexdigest()[:16]


class SecretsBackend(Protocol):
    def current_key_id(self) -> str: ...

    def get_master_key(self, key_id: str) -> bytes: ...

    def current_fingerprint(self) -> str: ...


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

    def current_fingerprint(self) -> str:
        return master_key_fingerprint(self._keys[self._current])


class TpmSecretsBackend(_MapBackend):
    """Master keys unsealed from the TPM at process start into memory only.

    The unsealed payload is `key_id:base64` lines (see `parse_master_keys`),
    sealed to the TPM under a PCR policy; it never touches disk in cleartext.
    The TPM interaction is isolated behind the injected `unseal` callable
    (returns the key text), so this adapter is testable without hardware;
    the running stack wires `unseal` to `tpm2_unseal` (see `tpm_unseal`).
    """

    def __init__(self, unseal: Callable[[], str]) -> None:
        keys, current = parse_master_keys(unseal())
        super().__init__(keys, current)


def tpm_unseal() -> str:
    """Unseal the master-key blob from the TPM.

    Runs `tpm2_unseal` against the persistent handle in
    `HYPROXY_TPM_SEALED_BLOB`, re-satisfying the PCR policy the object was
    sealed under (`HYPROXY_TPM_PCRS`; MUST match the sealing-time selection).
    Returns the `key_id:base64` text `parse_master_keys` consumes. Fails
    closed: a missing handle, tool failure, or empty output raises so the
    process refuses to start rather than run without keys.
    """
    import subprocess

    settings = get_settings()
    blob = settings.tpm_sealed_blob
    if not blob:
        raise RuntimeError(
            "HYPROXY_TPM_SEALED_BLOB is empty; set it to the persistent handle "
            "of the TPM-sealed master key (e.g. 0x81010001)"
        )
    try:
        out = subprocess.run(
            ["tpm2_unseal", "-c", blob, "-p", f"pcr:{settings.tpm_pcrs}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "tpm2_unseal not found; install tpm2-tools in the runtime environment"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"tpm2_unseal failed for handle {blob} under pcr:{settings.tpm_pcrs} "
            f"(PCR state drift after a firmware/kernel update requires resealing; "
            f"see docs/TPM_STEPS.md): {exc.stderr.strip()}"
        ) from exc
    if not out.stdout.strip():
        raise RuntimeError("tpm2_unseal returned an empty payload")
    return out.stdout


@lru_cache
def get_secrets_backend() -> SecretsBackend:
    backend = TpmSecretsBackend(tpm_unseal)
    _verify_fingerprint(backend, get_settings().master_key_fp)
    return backend


def _verify_fingerprint(backend: SecretsBackend, expected_fp: str) -> None:
    """Fail closed if the loaded master key is not the one this deployment pins.

    `HYPROXY_MASTER_KEY_FP` records the fingerprint of the master key the
    database is encrypted under (written by install.sh at seal time, only ever
    advanced together with a re-wrap). If the key unsealed at startup does not
    match it, a blob was resealed or swapped without re-wrapping the data: every
    decrypt would raise InvalidTag. Refuse to start with an actionable error
    rather than serve 500s. Empty (unset) skips the check for backwards
    compatibility with deployments provisioned before fingerprinting.
    """
    if not expected_fp:
        return
    actual_fp = backend.current_fingerprint()
    if actual_fp != expected_fp:
        raise RuntimeError(
            "master key fingerprint mismatch: the unsealed master key "
            f"({actual_fp}) is not the one this deployment is pinned to "
            f"(HYPROXY_MASTER_KEY_FP={expected_fp}). The TPM blob was resealed "
            "or replaced without re-wrapping the database, so stored ciphertext "
            "cannot be decrypted. Restore the original key from the FIPS backup "
            "and reseal, or re-wrap to the new key; see docs/TPM_STEPS.md."
        )

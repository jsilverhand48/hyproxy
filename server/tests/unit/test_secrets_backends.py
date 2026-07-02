"""Master-key parsing and the TPM backend adapter (TPM call isolated so the
adapter is testable without hardware)."""

import base64
import secrets

import pytest

from hyproxy.core.secrets import (
    MASTER_KEY_BYTES,
    TpmSecretsBackend,
    parse_master_keys,
    tpm_unseal,
)


def _key_text(*ids: str) -> str:
    return "\n".join(
        f"{kid}:{base64.b64encode(secrets.token_bytes(MASTER_KEY_BYTES)).decode()}" for kid in ids
    )


def test_parse_master_keys_current_is_last() -> None:
    keys, current = parse_master_keys("# comment\n" + _key_text("mk-1", "mk-2"))
    assert set(keys) == {"mk-1", "mk-2"}
    assert current == "mk-2"


def test_parse_rejects_wrong_length_and_empty() -> None:
    with pytest.raises(ValueError):
        parse_master_keys(f"mk-1:{base64.b64encode(b'short').decode()}")
    with pytest.raises(ValueError):
        parse_master_keys("# only comments\n")


def test_tpm_backend_adapter_serves_unsealed_keys() -> None:
    text = _key_text("mk-1", "mk-2")
    backend = TpmSecretsBackend(lambda: text)  # injected unseal, no hardware
    assert backend.current_key_id() == "mk-2"
    assert len(backend.get_master_key("mk-1")) == MASTER_KEY_BYTES
    with pytest.raises(KeyError):
        backend.get_master_key("mk-nope")


def test_tpm_unseal_is_a_deployment_hook() -> None:
    with pytest.raises(NotImplementedError):
        tpm_unseal()

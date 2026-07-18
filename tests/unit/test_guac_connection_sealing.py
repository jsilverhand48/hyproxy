"""Guacamole connection secret sealing round-trips and never stores plaintext."""

from pathlib import Path

from hyproxy.core.secrets import FileSecretsBackend, generate_master_key_file
from hyproxy.db.models import ResourceConnection
from hyproxy.guac.connections import seal_secret_params, unseal_secret_params


def _backend(tmp_path: Path) -> FileSecretsBackend:
    key_file = tmp_path / "master.keys"
    generate_master_key_file(key_file)
    return FileSecretsBackend(key_file)


def test_seal_unseal_roundtrip(tmp_path: Path) -> None:
    backend = _backend(tmp_path)
    params = {"username": "svc", "password": "p@ss w0rd", "private-key": "-----BEGIN-----"}
    key_id, blob, keys = seal_secret_params(backend, params)

    assert keys == sorted(params)
    assert b"p@ss w0rd" not in blob  # ciphertext, not plaintext
    row = ResourceConnection(
        resource_id=None,  # type: ignore[arg-type]
        protocol="ssh",
        hostname="h",
        port=22,
        params_json={},
        secret_ciphertext=blob,
        key_id=key_id,
        secret_keys=keys,
    )
    assert unseal_secret_params(backend, row) == params


def test_unseal_empty_when_no_secret(tmp_path: Path) -> None:
    backend = _backend(tmp_path)
    row = ResourceConnection(
        resource_id=None,  # type: ignore[arg-type]
        protocol="vnc",
        hostname="h",
        port=5900,
        params_json={},
        secret_ciphertext=None,
        key_id=None,
        secret_keys=[],
    )
    assert unseal_secret_params(backend, row) == {}

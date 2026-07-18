"""guacamole-lite token codec: round-trips under the shared key, mirrors the
envelope shape guacamole-lite expects, and fails to decrypt under a wrong key."""

import base64
import json
import secrets

import pytest

from hyproxy.guac.token import decrypt_token, load_cypher_key, mint_token


def test_roundtrip_and_envelope_shape() -> None:
    key = secrets.token_bytes(32)
    conn = {"connection": {"type": "rdp", "settings": {"hostname": "h", "port": "3389"}}}
    token = mint_token(key, conn)

    # The token is base64(JSON({"iv","value"})), both base64 strings.
    envelope = json.loads(base64.b64decode(token))
    assert set(envelope) == {"iv", "value"}
    assert len(base64.b64decode(envelope["iv"])) == 16

    assert decrypt_token(key, token) == conn


def test_wrong_key_does_not_decrypt() -> None:
    conn = {"connection": {"type": "vnc", "settings": {"hostname": "h", "port": "5900"}}}
    token = mint_token(secrets.token_bytes(32), conn)
    with pytest.raises(Exception):  # noqa: B017 -- padding/JSON error, either is fine
        decrypt_token(secrets.token_bytes(32), token)


def test_load_cypher_key_rejects_wrong_length() -> None:
    assert len(load_cypher_key(base64.b64encode(secrets.token_bytes(32)).decode())) == 32
    with pytest.raises(ValueError):
        load_cypher_key(base64.b64encode(secrets.token_bytes(16)).decode())

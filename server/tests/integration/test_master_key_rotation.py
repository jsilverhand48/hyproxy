"""Master-key rotation re-wraps every sealed blob to the new current key while
preserving plaintext. This is the file->TPM migration mechanism."""

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import create_user
from hyproxy.core.crypto import decrypt_blob, encrypt_blob
from hyproxy.core.reencrypt import rotate_to_current
from hyproxy.core.secrets import FileSecretsBackend, generate_master_key_file
from hyproxy.db.models import Resource, ResourceConnection, SigningKey, UserTotp

pytestmark = pytest.mark.integration


async def test_rotation_rewraps_all_sealed_blobs(
    db: AsyncSession, make_password_hash: Any, tmp_path: Path
) -> None:
    key_file = tmp_path / "master.keys"
    mk1 = generate_master_key_file(key_file)
    old = FileSecretsBackend(key_file)  # current = mk-1

    user = await create_user(db, make_password_hash, tier="standard", password="pw-rot")
    resource = Resource(name="rot-rdp", protocol="rdp", host="h", ports=[3389])
    db.add(resource)
    await db.flush()

    totp_kid, totp_blob = encrypt_blob(old, b"TOTPSECRET", "user_totp")
    sign_kid, sign_blob = encrypt_blob(old, b"-----PRIVATE-----", "signing_keys")
    conn_kid, conn_blob = encrypt_blob(old, b'{"password":"p"}', "resource_connections")
    assert totp_kid == sign_kid == conn_kid == mk1

    db.add_all(
        [
            UserTotp(user_id=user.id, secret_ciphertext=totp_blob, key_id=totp_kid),
            SigningKey(
                kid="k-rot", state="retiring", public_jwk={},
                private_key_ciphertext=sign_blob, key_id=sign_kid,
            ),
            ResourceConnection(
                resource_id=resource.id, protocol="rdp", hostname="h", port=3389,
                params_json={}, secret_ciphertext=conn_blob, key_id=conn_kid,
                secret_keys=["password"],
            ),
        ]
    )
    await db.flush()

    mk2 = generate_master_key_file(key_file)  # append a second key
    new = FileSecretsBackend(key_file)  # current = mk-2, still knows mk-1
    assert mk2 != mk1

    result = await rotate_to_current(db, new)
    assert result.target_key_id == mk2
    assert result.total == 3

    totp = await db.get(UserTotp, user.id)
    sign = await db.scalar(select(SigningKey).where(SigningKey.kid == "k-rot"))
    conn = await db.scalar(
        select(ResourceConnection).where(ResourceConnection.resource_id == resource.id)
    )
    assert totp is not None and sign is not None and conn is not None

    # All now under mk-2 and still decrypt to the original plaintext.
    for row, ct_attr, aad, expected in [
        (totp, "secret_ciphertext", "user_totp", b"TOTPSECRET"),
        (sign, "private_key_ciphertext", "signing_keys", b"-----PRIVATE-----"),
        (conn, "secret_ciphertext", "resource_connections", b'{"password":"p"}'),
    ]:
        assert row.key_id == mk2
        assert decrypt_blob(new, mk2, getattr(row, ct_attr), aad) == expected

    # Idempotent: a second rotation re-wraps nothing.
    again = await rotate_to_current(db, new)
    assert again.total == 0


async def test_rotation_skips_null_connection_secret(
    db: AsyncSession, tmp_path: Path
) -> None:
    key_file = tmp_path / "master.keys"
    generate_master_key_file(key_file)
    generate_master_key_file(key_file)
    backend = FileSecretsBackend(key_file)

    resource = Resource(name="nosecret", protocol="vnc", host="h", ports=[5900])
    db.add(resource)
    await db.flush()
    db.add(
        ResourceConnection(
            resource_id=resource.id, protocol="vnc", hostname="h", port=5900,
            params_json={}, secret_ciphertext=None, key_id=None, secret_keys=[],
        )
    )
    await db.flush()

    result = await rotate_to_current(db, backend)
    assert result.rewrapped["resource_connections"] == 0

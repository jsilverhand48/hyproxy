"""Master-key rotation: re-wrap every sealed blob under the backend's current
master key.

This is the migration path whenever a new master key becomes current, e.g.
when the TPM blob is resealed with a fresh key: add the new key as current,
run this to re-wrap all ciphertext to it, then retire the old key. Every
envelope carries the id of the master key
that sealed it, so old ciphertext keeps decrypting until it is re-wrapped; the
whole pass runs in one transaction.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.core.crypto import decrypt_blob, encrypt_blob
from hyproxy.core.secrets import SecretsBackend
from hyproxy.db.models import Base, ResourceConnection, SigningKey, UserTotp

# (model, ciphertext attr, key-id attr, AAD). AAD is the table name, matching how
# each site seals its blob.
_SEALED: list[tuple[type[Base], str, str, str]] = [
    (SigningKey, "private_key_ciphertext", "key_id", "signing_keys"),
    (UserTotp, "secret_ciphertext", "key_id", "user_totp"),
    (ResourceConnection, "secret_ciphertext", "key_id", "resource_connections"),
]


@dataclass(frozen=True)
class RotationResult:
    target_key_id: str
    rewrapped: dict[str, int]  # table name -> rows re-wrapped

    @property
    def total(self) -> int:
        return sum(self.rewrapped.values())


async def rotate_to_current(db: AsyncSession, backend: SecretsBackend) -> RotationResult:
    """Re-wrap every sealed blob not already under the current master key.

    Decrypt-then-encrypt with the same AAD, updating both the ciphertext and its
    key-id column. Idempotent: a second run re-wraps nothing."""
    target = backend.current_key_id()
    counts: dict[str, int] = {}
    for model, ct_attr, kid_attr, aad in _SEALED:
        rows = (await db.scalars(select(model))).all()
        n = 0
        for row in rows:
            blob = getattr(row, ct_attr)
            old_kid = getattr(row, kid_attr)
            if blob is None or old_kid == target:
                continue
            plaintext = decrypt_blob(backend, old_kid, blob, aad)
            new_kid, new_blob = encrypt_blob(backend, plaintext, aad)
            setattr(row, ct_attr, new_blob)
            setattr(row, kid_attr, new_kid)
            n += 1
        counts[model.__tablename__] = n
    await db.flush()
    return RotationResult(target_key_id=target, rewrapped=counts)

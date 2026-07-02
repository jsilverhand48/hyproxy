"""OIDC signing key lifecycle: publish-overlap-retire.

States: pending (in JWKS, not signing) -> active (signing; exactly one) ->
retiring (still verifies, in JWKS) -> retired (gone). Signing always uses the
single active key. Verification accepts active + retiring (+ pending, which is
harmless and warms caches before activation).
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, cast

from joserfc.jwk import ECKey
from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.core.crypto import decrypt_blob, encrypt_blob
from hyproxy.core.secrets import SecretsBackend
from hyproxy.db.models import SigningKey

# Retiring keys keep verifying for max access-token TTL plus clock skew.
RETIRE_BUFFER = timedelta(minutes=15)

PUBLISHED_STATES = ("pending", "active", "retiring")
_AAD = "signing_keys"


class NoActiveKeyError(RuntimeError):
    pass


def _generate(backend: SecretsBackend) -> SigningKey:
    key = ECKey.generate_key("P-256", private=True)
    kid = uuid.uuid4().hex
    public = key.as_dict(private=False)
    public["kid"] = kid
    public["use"] = "sig"
    public["alg"] = "ES256"
    key_id, blob = encrypt_blob(backend, key.as_pem(private=True), _AAD)
    return SigningKey(
        kid=kid,
        alg="ES256",
        state="pending",
        public_jwk=public,
        private_key_ciphertext=blob,
        key_id=key_id,
    )


async def create_pending(session: AsyncSession, backend: SecretsBackend) -> SigningKey:
    """New pending key, published in JWKS immediately so caches warm up."""
    row = _generate(backend)
    session.add(row)
    await session.flush()
    return row


async def activate_pending(session: AsyncSession, now: datetime) -> SigningKey:
    """Promote the newest pending key to active; demote the old active to retiring."""
    pending = await session.scalar(
        select(SigningKey)
        .where(SigningKey.state == "pending")
        .order_by(SigningKey.created_at.desc())
        .limit(1)
    )
    if pending is None:
        raise NoActiveKeyError("no pending key to activate; run rotate-signing-key first")
    await session.execute(
        update(SigningKey)
        .where(SigningKey.state == "active")
        .values(state="retiring", retiring_at=now)
    )
    pending.state = "active"
    pending.activated_at = now
    await session.flush()
    return pending


async def bootstrap_if_empty(session: AsyncSession, backend: SecretsBackend, now: datetime) -> None:
    """First run: create and immediately activate a key so signing works."""
    existing = await session.scalar(select(SigningKey.id).limit(1))
    if existing is None:
        await create_pending(session, backend)
        await activate_pending(session, now)


async def get_active_signing_key(
    session: AsyncSession, backend: SecretsBackend
) -> tuple[str, ECKey]:
    row = await session.scalar(select(SigningKey).where(SigningKey.state == "active"))
    if row is None:
        raise NoActiveKeyError("no active signing key")
    pem = decrypt_blob(backend, row.key_id, row.private_key_ciphertext, _AAD)
    return row.kid, ECKey.import_key(pem.decode())


async def get_verification_jwks(session: AsyncSession) -> dict[str, Any]:
    rows = (
        await session.scalars(
            select(SigningKey)
            .where(SigningKey.state.in_(PUBLISHED_STATES))
            .order_by(SigningKey.created_at)
        )
    ).all()
    return {"keys": [row.public_jwk for row in rows]}


async def gc_retired(session: AsyncSession, now: datetime) -> int:
    """Retire keys whose retiring grace window has passed. Returns count retired."""
    result = cast(
        CursorResult[Any],
        await session.execute(
            update(SigningKey)
            .where(SigningKey.state == "retiring", SigningKey.retiring_at <= now - RETIRE_BUFFER)
            .values(state="retired", retired_at=now)
        ),
    )
    return result.rowcount or 0

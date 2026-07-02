"""One-time recovery codes: ~50 bits each, shown once, stored argon2id-hashed.

A new batch invalidates all previous unused codes. Consumption marks the code
used inside the caller's transaction.
"""

import secrets
import uuid
from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import RecoveryCode
from hyproxy.security.passwords import hash_password, verify_password

# Unambiguous characters (no 0/O, 1/I/L): 31 symbols, ~4.95 bits each, ~50 bits per code.
ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_LENGTH = 10
BATCH_SIZE = 10


def _generate_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
    return f"{raw[:5]}-{raw[5:]}"


def normalize(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


async def issue_batch(session: AsyncSession, user_id: uuid.UUID) -> list[str]:
    """Replace any unused codes with a fresh batch. Returns plaintext codes (show once)."""
    await session.execute(
        delete(RecoveryCode).where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
    )
    batch_id = uuid.uuid4()
    codes = [_generate_code() for _ in range(BATCH_SIZE)]
    for code in codes:
        session.add(
            RecoveryCode(
                user_id=user_id, batch_id=batch_id, code_hash=hash_password(normalize(code))
            )
        )
    await session.flush()
    return codes


async def consume(session: AsyncSession, user_id: uuid.UUID, code: str, now: datetime) -> bool:
    """Verify a code against the user's unused codes; mark it used on match."""
    normalized = normalize(code)
    rows = (
        await session.scalars(
            select(RecoveryCode)
            .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
            .with_for_update()
        )
    ).all()
    for row in rows:
        if verify_password(row.code_hash, normalized):
            row.used_at = now
            await session.flush()
            return True
    return False

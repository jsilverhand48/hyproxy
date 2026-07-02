"""Authorization code issue/consume. Codes are stored only as SHA-256 hashes,
live 60 seconds, and are strictly single-use: consuming is one conditional
UPDATE, and a second presentation revokes the issuing session (replay defense).
"""

from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core.crypto import new_token, sha256_hex
from hyproxy.db.models import AuthCode, Session


async def issue_code(
    db: AsyncSession,
    *,
    session: Session,
    client_id: str,
    redirect_uri: str,
    scope: str,
    nonce: str,
    code_challenge: str,
    now: datetime,
) -> str:
    code = new_token(32)
    db.add(
        AuthCode(
            code_hash=sha256_hex(code),
            client_id=client_id,
            user_id=session.user_id,
            session_id=session.id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            auth_time=session.issued_at,
            expires_at=now + timedelta(seconds=get_settings().auth_code_ttl),
        )
    )
    await db.flush()
    return code


async def consume_code(db: AsyncSession, code: str, now: datetime) -> AuthCode | None:
    """Single-use consumption. Returns the row on first valid use, else None."""
    code_hash = sha256_hex(code)
    result = await db.execute(
        update(AuthCode)
        .where(
            AuthCode.code_hash == code_hash,
            AuthCode.consumed_at.is_(None),
            AuthCode.expires_at > now,
        )
        .values(consumed_at=now)
        .returning(AuthCode.code_hash)
    )
    if result.scalar_one_or_none() is None:
        return None
    return await db.get(AuthCode, code_hash)


async def find_consumed(db: AsyncSession, code: str) -> AuthCode | None:
    """Detects code replay: an already-consumed (even expired) code."""
    row = await db.scalar(select(AuthCode).where(AuthCode.code_hash == sha256_hex(code)))
    if row is not None and row.consumed_at is not None:
        return row
    return None

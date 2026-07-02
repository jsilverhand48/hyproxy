"""Refresh token rotation with family-wide reuse detection.

Every refresh token is single-use; using one mints a child in the same
family. Presenting an already-used token means theft (either the attacker or
the legitimate client holds a stale copy), so the whole family AND the
session are revoked.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.core.crypto import new_token, sha256_hex
from hyproxy.db.models import RefreshToken, Session


async def issue_family(
    db: AsyncSession,
    *,
    session: Session,
    client_id: str,
    scope: str,
    jkt: str,
    now: datetime,
) -> str:
    """New refresh token starting a new family. Expiry is capped at the
    session's absolute expiry (the 6h outer bound)."""
    token = new_token(48)
    db.add(
        RefreshToken(
            token_hash=sha256_hex(token),
            session_id=session.id,
            family_id=uuid.uuid4(),
            parent_id=None,
            client_id=client_id,
            user_id=session.user_id,
            dpop_jkt=jkt,
            scope=scope,
            issued_at=now,
            expires_at=session.absolute_expires_at,
        )
    )
    await db.flush()
    return token


async def find(db: AsyncSession, token: str) -> RefreshToken | None:
    result: RefreshToken | None = await db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(token))
    )
    return result


async def rotate(db: AsyncSession, row: RefreshToken, *, now: datetime) -> str:
    """Mark `row` used and mint its child in the same family."""
    row.used_at = now
    token = new_token(48)
    db.add(
        RefreshToken(
            token_hash=sha256_hex(token),
            session_id=row.session_id,
            family_id=row.family_id,
            parent_id=row.id,
            client_id=row.client_id,
            user_id=row.user_id,
            dpop_jkt=row.dpop_jkt,
            scope=row.scope,
            issued_at=now,
            expires_at=row.expires_at,  # family stays capped at the session bound
        )
    )
    await db.flush()
    return token


async def revoke_family(db: AsyncSession, family_id: uuid.UUID) -> None:
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )


async def revoke_for_session(db: AsyncSession, session_id: uuid.UUID) -> None:
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.session_id == session_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )

"""Postgres-backed DPoP jti replay cache."""

from datetime import datetime
from typing import Any, cast

from sqlalchemy import CursorResult
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import DpopJtiSeen


class PgJtiReplayCache:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def check_and_store(self, jkt: str, jti: str, expires_at: datetime) -> bool:
        result = cast(
            CursorResult[Any],
            await self._session.execute(
                pg_insert(DpopJtiSeen)
                .values(jkt=jkt, jti=jti, expires_at=expires_at)
                .on_conflict_do_nothing(index_elements=["jkt", "jti"])
            ),
        )
        return bool(result.rowcount)

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import DpopJtiSeen
from hyproxy.idp.oidc.replay import PgJtiReplayCache

pytestmark = pytest.mark.integration


async def test_first_use_stores_replay_rejected(db: AsyncSession) -> None:
    cache = PgJtiReplayCache(db)
    expires = datetime.now(UTC) + timedelta(minutes=5)
    assert await cache.check_and_store("jkt-1", "jti-abc", expires) is True
    assert await cache.check_and_store("jkt-1", "jti-abc", expires) is False
    # Same jti under a different key is a different entry.
    assert await cache.check_and_store("jkt-2", "jti-abc", expires) is True


async def test_gc_removes_expired_entries(db: AsyncSession) -> None:
    cache = PgJtiReplayCache(db)
    now = datetime.now(UTC)
    await cache.check_and_store("jkt-gc", "expired", now - timedelta(seconds=1))
    await cache.check_and_store("jkt-gc", "live", now + timedelta(minutes=5))
    await db.execute(delete(DpopJtiSeen).where(DpopJtiSeen.expires_at <= now))
    remaining = await db.scalar(
        select(func.count()).select_from(DpopJtiSeen).where(DpopJtiSeen.jkt == "jkt-gc")
    )
    assert remaining == 1

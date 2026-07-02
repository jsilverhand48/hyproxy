from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from hyproxy.config import get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(get_settings().db_url, pool_pre_ping=True)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


@asynccontextmanager
async def db_session() -> AsyncIterator[AsyncSession]:
    """One transaction per unit of work; commits on success, rolls back on error."""
    async with get_sessionmaker()() as session:
        async with session.begin():
            yield session


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with db_session() as session:
        yield session


def reset_engine() -> None:
    """Test hook: forget the cached engine/sessionmaker (settings may have changed)."""
    global _engine, _sessionmaker
    _engine = None
    _sessionmaker = None

import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine

from hyproxy.admin.app import create_app as create_admin_app
from hyproxy.core.secrets import FileSecretsBackend, generate_master_key_file
from hyproxy.db.engine import get_db
from hyproxy.db.models import Base
from hyproxy.idp.app import create_app as create_idp_app
from hyproxy.security.passwords import hash_password

_DEV_SOCKET = Path(__file__).resolve().parent.parent / ".dev" / "pgsocket"


def test_db_url() -> str | None:
    url = os.environ.get("hyproxy_TEST_DB_URL")
    if url:
        return url
    if _DEV_SOCKET.exists():
        return f"postgresql+asyncpg://postgres@/hyproxy_test?host={_DEV_SOCKET}"
    return None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if test_db_url() is not None:
        return
    skip = pytest.mark.skip(reason="no test database (set hyproxy_TEST_DB_URL or make db-up)")
    for item in items:
        if "integration" in item.keywords or "e2e" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
async def test_engine() -> AsyncIterator[AsyncEngine]:
    url = test_db_url()
    assert url is not None
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db(test_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Session wrapped in an outer transaction that is always rolled back.

    join_transaction_mode="create_savepoint" lets code under test call commit()
    without escaping the enclosing rollback.
    """
    async with test_engine.connect() as conn:
        trans = await conn.begin()
        session = AsyncSession(
            bind=conn, expire_on_commit=False, join_transaction_mode="create_savepoint"
        )
        try:
            yield session
        finally:
            await session.close()
            await trans.rollback()


@pytest.fixture
async def idp_client(db: AsyncSession) -> AsyncIterator[httpx.AsyncClient]:
    """IdP app wired to the rollback-wrapped test session."""
    app = create_idp_app()

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    app.dependency_overrides[get_db] = override_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://idp.test") as client:
        yield client


@pytest.fixture
async def admin_client(db: AsyncSession) -> AsyncIterator[httpx.AsyncClient]:
    """Admin API app wired to the same rollback-wrapped test session."""
    app = create_admin_app()

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    app.dependency_overrides[get_db] = override_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://admin.test") as client:
        yield client


@pytest.fixture
def secrets_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FileSecretsBackend:
    """File-backed secrets for tests, patched into every module that resolved it."""
    path = tmp_path / "master.keys"
    generate_master_key_file(path)
    backend = FileSecretsBackend(path)
    monkeypatch.setattr("hyproxy.core.secrets.get_secrets_backend", lambda: backend)
    monkeypatch.setattr("hyproxy.idp.web.routes.get_secrets_backend", lambda: backend)
    return backend


@pytest.fixture(scope="session")
def password_hash_cache() -> dict[str, str]:
    return {}


@pytest.fixture
def make_password_hash(password_hash_cache: dict[str, str]) -> Callable[[str], str]:
    """argon2 is intentionally slow; cache hashes across tests."""

    def _make(password: str) -> str:
        if password not in password_hash_cache:
            password_hash_cache[password] = hash_password(password)
        return password_hash_cache[password]

    return _make

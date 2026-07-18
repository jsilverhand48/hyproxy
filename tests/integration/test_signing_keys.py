from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.core import keys as key_service
from hyproxy.core.secrets import FileSecretsBackend, generate_master_key_file
from hyproxy.db.engine import get_db
from hyproxy.db.models import SigningKey
from hyproxy.idp.app import create_app

pytestmark = pytest.mark.integration


@pytest.fixture
def backend(tmp_path: Path) -> FileSecretsBackend:
    path = tmp_path / "master.keys"
    generate_master_key_file(path)
    return FileSecretsBackend(path)


async def test_bootstrap_creates_single_active_key(
    db: AsyncSession, backend: FileSecretsBackend
) -> None:
    now = datetime.now(UTC)
    await key_service.bootstrap_if_empty(db, backend, now)
    kid, private = await key_service.get_active_signing_key(db, backend)
    assert private.as_dict(private=True).get("d")  # usable private key
    # Idempotent
    await key_service.bootstrap_if_empty(db, backend, now)
    rows = (await db.scalars(select(SigningKey))).all()
    assert len(rows) == 1
    assert rows[0].kid == kid


async def test_rotation_lifecycle(db: AsyncSession, backend: FileSecretsBackend) -> None:
    now = datetime.now(UTC)
    await key_service.bootstrap_if_empty(db, backend, now)
    first_kid, _ = await key_service.get_active_signing_key(db, backend)

    pending = await key_service.create_pending(db, backend)
    jwks = await key_service.get_verification_jwks(db)
    kids = {k["kid"] for k in jwks["keys"]}
    assert kids == {first_kid, pending.kid}  # overlap published before activation

    await key_service.activate_pending(db, now)
    active_kid, _ = await key_service.get_active_signing_key(db, backend)
    assert active_kid == pending.kid

    old = await db.scalar(select(SigningKey).where(SigningKey.kid == first_kid))
    assert old is not None
    assert old.state == "retiring"
    assert old.retiring_at is not None

    # Retiring key still published (verification overlap)
    jwks = await key_service.get_verification_jwks(db)
    assert {k["kid"] for k in jwks["keys"]} == {first_kid, pending.kid}


async def test_gc_respects_retire_buffer(db: AsyncSession, backend: FileSecretsBackend) -> None:
    now = datetime.now(UTC)
    await key_service.bootstrap_if_empty(db, backend, now)
    await key_service.create_pending(db, backend)
    await key_service.activate_pending(db, now)

    # Within the buffer: nothing retired.
    assert await key_service.gc_retired(db, now + timedelta(minutes=5)) == 0
    # Past the buffer: the retiring key is retired and leaves JWKS.
    assert await key_service.gc_retired(db, now + timedelta(minutes=20)) == 1
    jwks = await key_service.get_verification_jwks(db)
    assert len(jwks["keys"]) == 1


async def test_activate_without_pending_raises(db: AsyncSession) -> None:
    with pytest.raises(key_service.NoActiveKeyError):
        await key_service.activate_pending(db, datetime.now(UTC))


async def test_jwks_endpoint_serves_published_keys(
    db: AsyncSession, backend: FileSecretsBackend
) -> None:
    await key_service.bootstrap_if_empty(db, backend, datetime.now(UTC))
    app = create_app()

    async def override_db() -> AsyncSession:
        return db

    app.dependency_overrides[get_db] = override_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/oidc/jwks")
    assert resp.status_code == 200
    assert resp.headers["cache-control"].startswith("max-age=")
    body = resp.json()
    assert len(body["keys"]) == 1
    jwk = body["keys"][0]
    assert jwk["kty"] == "EC" and jwk["alg"] == "ES256" and "d" not in jwk


async def test_discovery_document() -> None:
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["response_types_supported"] == ["code"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["dpop_signing_alg_values_supported"] == ["ES256"]
    assert doc["token_endpoint_auth_methods_supported"] == ["none"]
    assert doc["jwks_uri"].endswith("/oidc/jwks")

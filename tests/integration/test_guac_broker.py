"""Guacamole broker: policy-checked token minting, audit, single-use grants."""

import base64
import secrets as pysecrets
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import create_user
from hyproxy.config import get_settings
from hyproxy.core.crypto import sha256_hex
from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import (
    AuditLog,
    GuacGrant,
    Policy,
    Resource,
    ResourceConnection,
    Role,
    User,
    UserRole,
)
from hyproxy.guac import broker
from hyproxy.guac.connections import seal_secret_params
from hyproxy.guac.token import decrypt_token

pytestmark = pytest.mark.integration


@pytest.fixture
def cypher_key(monkeypatch: pytest.MonkeyPatch) -> bytes:
    raw = pysecrets.token_bytes(32)
    monkeypatch.setattr(get_settings(), "guac_cypher_key", base64.b64encode(raw).decode())
    return raw


async def _seed_allowed(
    db: AsyncSession, backend: FileSecretsBackend, make_password_hash: Any, *, with_policy: bool
) -> tuple[User, Resource, ResourceConnection]:
    user = await create_user(db, make_password_hash, tier="standard", password="pw-guac-broker")
    role = Role(name="rdp-users")
    resource = Resource(name="lab-rdp", protocol="rdp", host="10.0.0.20", ports=[3389])
    db.add_all([role, resource])
    await db.flush()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    key_id, blob, keys = seal_secret_params(backend, {"username": "svc", "password": "p"})
    conn = ResourceConnection(
        resource_id=resource.id,
        protocol="rdp",
        hostname="10.0.0.20",
        port=3389,
        params_json={"security": "nla"},
        secret_ciphertext=blob,
        key_id=key_id,
        secret_keys=keys,
    )
    db.add(conn)
    if with_policy:
        db.add(Policy(role_id=role.id, resource_id=resource.id, action="allow", enabled=True))
    await db.flush()
    return user, resource, conn


async def test_allow_mints_token_grant_and_audit(
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
    make_password_hash: Any,
    cypher_key: bytes,
) -> None:
    user, resource, conn = await _seed_allowed(
        db, secrets_backend, make_password_hash, with_policy=True
    )
    now = datetime.now(UTC)
    result = await broker.issue_tunnel(
        db, secrets_backend, user_id=user.id, resource_id=resource.id,
        source_ip="10.0.0.9", now=now,
    )
    assert result.allowed and result.token is not None
    assert result.protocol == "rdp"

    decoded = decrypt_token(cypher_key, result.token)
    settings = decoded["connection"]["settings"]
    assert decoded["connection"]["type"] == "rdp"
    assert settings["hostname"] == "10.0.0.20" and settings["port"] == "3389"
    assert settings["security"] == "nla"
    assert settings["password"] == "p"  # secret resolved into the token, not the browser response

    grant = await db.get(GuacGrant, sha256_hex(result.token))
    assert grant is not None and grant.user_id == user.id and grant.connection_id == conn.id

    audits = (await db.scalars(select(AuditLog).where(AuditLog.resource_id == resource.id))).all()
    assert any(a.decision == "allow" for a in audits)


async def test_deny_without_policy_audits_and_no_grant(
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
    make_password_hash: Any,
    cypher_key: bytes,
) -> None:
    user, resource, _ = await _seed_allowed(
        db, secrets_backend, make_password_hash, with_policy=False
    )
    now = datetime.now(UTC)
    result = await broker.issue_tunnel(
        db, secrets_backend, user_id=user.id, resource_id=resource.id,
        source_ip="10.0.0.9", now=now,
    )
    assert not result.allowed and result.token is None
    assert (await db.scalars(select(GuacGrant))).first() is None
    audits = (await db.scalars(select(AuditLog).where(AuditLog.resource_id == resource.id))).all()
    assert audits and all(a.decision == "deny" for a in audits)


async def test_no_connection_denies(
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
    make_password_hash: Any,
    cypher_key: bytes,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password="pw-x")
    resource = Resource(name="bare", protocol="rdp", host="h", ports=[3389])
    db.add(resource)
    await db.flush()
    result = await broker.issue_tunnel(
        db, secrets_backend, user_id=user.id, resource_id=resource.id,
        source_ip="10.0.0.9", now=datetime.now(UTC),
    )
    assert not result.allowed and result.reason == "no_connection"


async def test_guac_disabled_when_no_cypher_key(
    db: AsyncSession, secrets_backend: FileSecretsBackend, make_password_hash: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "guac_cypher_key", "")
    user = await create_user(db, make_password_hash, tier="standard", password="pw-x")
    resource = Resource(name="bare2", protocol="rdp", host="h", ports=[3389])
    db.add(resource)
    await db.flush()
    result = await broker.issue_tunnel(
        db, secrets_backend, user_id=user.id, resource_id=resource.id,
        source_ip="10.0.0.9", now=datetime.now(UTC),
    )
    assert not result.allowed and result.reason == "guac_disabled"


async def test_grant_single_use_ip_bound_and_expiring(
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
    make_password_hash: Any,
    cypher_key: bytes,
) -> None:
    user, resource, _ = await _seed_allowed(
        db, secrets_backend, make_password_hash, with_policy=True
    )
    now = datetime.now(UTC)
    result = await broker.issue_tunnel(
        db, secrets_backend, user_id=user.id, resource_id=resource.id,
        source_ip="10.0.0.9", now=now,
    )
    assert result.token is not None
    token = result.token

    # Wrong source IP never consumes.
    assert await broker.consume_grant(db, token, source_ip="10.0.0.99", now=now) is False
    # Correct IP consumes exactly once.
    assert await broker.consume_grant(db, token, source_ip="10.0.0.9", now=now) is True
    assert await broker.consume_grant(db, token, source_ip="10.0.0.9", now=now) is False


async def test_grant_expired_not_consumable(
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
    make_password_hash: Any,
    cypher_key: bytes,
) -> None:
    user, resource, _ = await _seed_allowed(
        db, secrets_backend, make_password_hash, with_policy=True
    )
    now = datetime.now(UTC)
    result = await broker.issue_tunnel(
        db, secrets_backend, user_id=user.id, resource_id=resource.id,
        source_ip="10.0.0.9", now=now,
    )
    assert result.token is not None
    later = now + timedelta(seconds=get_settings().guac_grant_ttl + 5)
    assert await broker.consume_grant(db, result.token, source_ip="10.0.0.9", now=later) is False


async def test_consume_is_user_bound(
    db: AsyncSession,
    secrets_backend: FileSecretsBackend,
    make_password_hash: Any,
    cypher_key: bytes,
) -> None:
    import uuid

    user, resource, _ = await _seed_allowed(
        db, secrets_backend, make_password_hash, with_policy=True
    )
    now = datetime.now(UTC)
    result = await broker.issue_tunnel(
        db, secrets_backend, user_id=user.id, resource_id=resource.id,
        source_ip="10.0.0.9", now=now,
    )
    assert result.token is not None
    # A different user cannot consume this user's grant.
    assert (
        await broker.consume_grant(
            db, result.token, source_ip="10.0.0.9", now=now, user_id=uuid.uuid4()
        )
        is False
    )
    # The owner can.
    assert (
        await broker.consume_grant(
            db, result.token, source_ip="10.0.0.9", now=now, user_id=user.id
        )
        is True
    )


async def test_token_and_consume_endpoints_require_gateway_session(authz_client: Any) -> None:
    import uuid

    tok = await authz_client.post("/guac/token", json={"resource_id": str(uuid.uuid4())})
    assert tok.status_code == 401 and tok.json()["error"] == "auth_required"

    con = await authz_client.post("/guac/consume", json={"token": "anything"})
    assert con.status_code == 401 and con.json()["reason"] == "auth_required"

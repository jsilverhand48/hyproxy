"""Guacamole tunnel broker.

Given an authenticated, policy-allowed user and a target resource, mint a
short-lived, single-use guacamole-lite token carrying the resolved connection
(secrets unsealed only at mint time). The browser never sees raw connection
credentials, only the opaque token. Every decision writes an audit_log row in
the same transaction, exactly like the data-plane ext-authz check.

The single-use consume runs when the data plane forward-auths the tunnel
WebSocket connect (source-IP bound, expiry enforced), so a leaked token is
usable at most once and only from the same client IP within the TTL.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.authz.decision import evaluate_access
from hyproxy.config import get_settings
from hyproxy.core.crypto import sha256_hex
from hyproxy.core.secrets import SecretsBackend
from hyproxy.db.models import AuditLog, GuacGrant, Resource, ResourceConnection
from hyproxy.guac.connections import unseal_secret_params
from hyproxy.guac.token import load_cypher_key, mint_token


@dataclass(frozen=True)
class BrokerResult:
    allowed: bool
    reason: str
    token: str | None = None
    protocol: str | None = None
    expires_at: datetime | None = None


async def _audit(
    db: AsyncSession,
    *,
    user_id: object,
    resource_id: object,
    port: int | None,
    decision: str,
    reason: str,
    source_ip: str,
) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            resource_id=resource_id,
            port=port,
            decision=decision,
            reason=reason,
            source_ip=source_ip,
        )
    )
    await db.flush()


async def issue_tunnel(
    db: AsyncSession,
    backend: SecretsBackend,
    *,
    user_id: uuid.UUID,
    resource_id: uuid.UUID,
    source_ip: str,
    now: datetime,
) -> BrokerResult:
    settings = get_settings()
    if not settings.guac_cypher_key:
        return BrokerResult(False, "guac_disabled")

    resource = await db.get(Resource, resource_id)
    if resource is None or not resource.enabled:
        await _audit(
            db, user_id=user_id, resource_id=resource_id, port=None,
            decision="deny", reason="unknown_resource", source_ip=source_ip,
        )
        return BrokerResult(False, "unknown_resource")

    connection = await db.scalar(
        select(ResourceConnection).where(ResourceConnection.resource_id == resource_id)
    )
    if connection is None:
        await _audit(
            db, user_id=user_id, resource_id=resource_id, port=None,
            decision="deny", reason="no_connection", source_ip=source_ip,
        )
        return BrokerResult(False, "no_connection")

    port = connection.port
    access = await evaluate_access(
        db, user_id=user_id, resource_id=resource_id, port=port, path="/", now=now
    )
    decision = access.decision
    await _audit(
        db, user_id=user_id, resource_id=resource_id, port=port,
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason, source_ip=source_ip,
    )
    if not decision.allowed:
        return BrokerResult(False, decision.reason)

    conn_settings: dict[str, Any] = {str(k): str(v) for k, v in connection.params_json.items()}
    conn_settings.update(unseal_secret_params(backend, connection))
    conn_settings["hostname"] = connection.hostname
    conn_settings["port"] = str(connection.port)
    conn_obj = {"connection": {"type": connection.protocol, "settings": conn_settings}}

    key = load_cypher_key(settings.guac_cypher_key)
    token = mint_token(key, conn_obj)
    expires_at = now + timedelta(seconds=settings.guac_grant_ttl)
    db.add(
        GuacGrant(
            token_hash=sha256_hex(token),
            user_id=user_id,
            resource_id=resource_id,
            connection_id=connection.id,
            source_ip=source_ip,
            expires_at=expires_at,
        )
    )
    await db.flush()
    return BrokerResult(
        True, "allowed", token=token, protocol=connection.protocol, expires_at=expires_at
    )


async def consume_grant(
    db: AsyncSession,
    token: str,
    *,
    source_ip: str,
    now: datetime,
    user_id: uuid.UUID | None = None,
) -> bool:
    """Atomically consume a grant: valid, unexpired, unconsumed, IP-matched, and
    (when given) owned by user_id. Returns True exactly once per minted token."""
    conditions = [
        GuacGrant.token_hash == sha256_hex(token),
        GuacGrant.consumed_at.is_(None),
        GuacGrant.expires_at > now,
        GuacGrant.source_ip == source_ip,
    ]
    if user_id is not None:
        conditions.append(GuacGrant.user_id == user_id)
    result = cast(
        CursorResult[Any],
        await db.execute(update(GuacGrant).where(*conditions).values(consumed_at=now)),
    )
    return result.rowcount == 1

"""RTSP stream broker.

Given an authenticated, policy-allowed user, a target camera resource, and the
camera credentials the viewer just typed, mint a short-lived single-use token
carrying the resolved RTSP URL. Every decision writes an audit_log row in the
same transaction, exactly like the guac broker and the data-plane ext-authz
check.

The one structural difference from `hyproxy.guac.broker`: nothing is unsealed
here, because nothing is stored. RTSP credentials arrive in the mint request,
travel only inside the encrypted token, and are gone when the token expires.
The audit trail records that a user opened a stream, never what they typed.

The single-use consume runs when the data plane forward-auths the bridge
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
from hyproxy.core.sealedtoken import load_cypher_key, mint_token
from hyproxy.db.models import AuditLog, Resource, ResourceConnection, RtspGrant
from hyproxy.rtsp.urls import build_rtsp_url

RTSP_PROTOCOL = "rtsp"


@dataclass(frozen=True)
class BrokerResult:
    allowed: bool
    reason: str
    token: str | None = None
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


async def issue_stream(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    resource_id: uuid.UUID,
    rtsp_username: str,
    rtsp_password: str,
    source_ip: str,
    now: datetime,
) -> BrokerResult:
    settings = get_settings()
    if not settings.rtsp_cypher_key:
        return BrokerResult(False, "rtsp_disabled")

    resource = await db.get(Resource, resource_id)
    if resource is None or not resource.enabled:
        await _audit(
            db,
            user_id=user_id,
            resource_id=resource_id,
            port=None,
            decision="deny",
            reason="unknown_resource",
            source_ip=source_ip,
        )
        return BrokerResult(False, "unknown_resource")

    connection = await db.scalar(
        select(ResourceConnection).where(ResourceConnection.resource_id == resource_id)
    )
    if connection is None or connection.protocol != RTSP_PROTOCOL:
        await _audit(
            db,
            user_id=user_id,
            resource_id=resource_id,
            port=None,
            decision="deny",
            reason="no_connection",
            source_ip=source_ip,
        )
        return BrokerResult(False, "no_connection")

    port = connection.port
    access = await evaluate_access(
        db, user_id=user_id, resource_id=resource_id, port=port, path="/", now=now
    )
    decision = access.decision
    await _audit(
        db,
        user_id=user_id,
        resource_id=resource_id,
        port=port,
        decision="allow" if decision.allowed else "deny",
        reason=decision.reason,
        source_ip=source_ip,
    )
    if not decision.allowed:
        return BrokerResult(False, decision.reason)

    params = {str(k): str(v) for k, v in connection.params_json.items()}
    stream: dict[str, Any] = {
        "url": build_rtsp_url(connection, username=rtsp_username, password=rtsp_password),
        # Camera audio is usually G.711, which MSE cannot play, so it is dropped
        # unless the admin opted into an AAC transcode on the connection.
        "audio": "aac" if params.get("audio") == "aac" else "none",
        "max_seconds": settings.rtsp_max_stream_secs,
        "user_id": str(user_id),
    }

    key = load_cypher_key(settings.rtsp_cypher_key)
    token = mint_token(key, {"stream": stream})
    expires_at = now + timedelta(seconds=settings.rtsp_grant_ttl)
    db.add(
        RtspGrant(
            token_hash=sha256_hex(token),
            user_id=user_id,
            resource_id=resource_id,
            connection_id=connection.id,
            source_ip=source_ip,
            expires_at=expires_at,
        )
    )
    await db.flush()
    return BrokerResult(True, "allowed", token=token, expires_at=expires_at)


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
        RtspGrant.token_hash == sha256_hex(token),
        RtspGrant.consumed_at.is_(None),
        RtspGrant.expires_at > now,
        RtspGrant.source_ip == source_ip,
    ]
    if user_id is not None:
        conditions.append(RtspGrant.user_id == user_id)
    result = cast(
        CursorResult[Any],
        await db.execute(update(RtspGrant).where(*conditions).values(consumed_at=now)),
    )
    return result.rowcount == 1

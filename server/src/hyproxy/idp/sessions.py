"""IdP session lifecycle: creation, cookie binding, liveness, revocation.

check_request (the resource-server side: JWT + DPoP + liveness) is added with
the OIDC core; this module owns the row-level session semantics shared by the
login surface and the token endpoints.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import Response
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.audit.events import AuthEventType, emit
from hyproxy.config import get_settings
from hyproxy.core.crypto import constant_time_equals, new_token, sha256_hex
from hyproxy.db.models import Session, User

if TYPE_CHECKING:
    from hyproxy.idp.oidc import tokens

SESSION_COOKIE = "__Host-idp_sid"


async def create_session(
    db: AsyncSession, *, user: User, source_ip: str, amr: list[str], now: datetime
) -> tuple[Session, str]:
    """Returns (session, cookie_value). Only the hash of the cookie secret is stored."""
    secret = new_token(32)
    session = Session(
        user_id=user.id,
        cookie_secret_hash=sha256_hex(secret),
        source_ip=source_ip,
        auth_tier=user.auth_tier,  # frozen at login time
        amr=amr,
        mfa_verified=True,
        issued_at=now,
        last_seen_at=now,
        absolute_expires_at=now + timedelta(seconds=get_settings().refresh_abs_ttl),
    )
    db.add(session)
    await db.flush()
    await emit(
        db,
        AuthEventType.SESSION_CREATED,
        source_ip=source_ip,
        success=True,
        user_id=user.id,
        session_id=session.id,
    )
    return session, f"{session.id}.{secret}"


async def reissue_cookie(db: AsyncSession, session: Session) -> str:
    """Mint a fresh cookie secret for an existing session and return the new
    cookie value. Only the hash is stored. Used to re-attach the browser on an
    idempotent login replay, where the original secret (known only to the first
    response) cannot be recovered."""
    secret = new_token(32)
    session.cookie_secret_hash = sha256_hex(secret)
    await db.flush()
    return f"{session.id}.{secret}"


def set_session_cookie(response: Response, cookie_value: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        cookie_value,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=get_settings().refresh_abs_ttl,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


async def check_liveness(
    db: AsyncSession, session: Session, *, source_ip: str, now: datetime, enforce_ip: bool = True
) -> bool:
    """Shared per-request session gate: revoked/stale, 6h absolute bound,
    30 min idle timeout (revokes on trip), and source-IP binding (marks stale
    on change, forcing full re-auth). Touches last_seen_at on success.

    enforce_ip=False skips the source-IP binding: used by the OIDC token
    endpoint, whose caller is the OAuth client (e.g. the gateway's server-side
    backchannel), not the browser, so its socket IP never matches the session.
    The exchange is bound instead by single-use code, PKCE, and DPoP. IP binding
    stays enforced on the data-plane resource path (check_request, whose caller
    IP is observed at the single ingress and is stable). The browser session-
    cookie resolver (get_session_from_cookie) also passes enforce_ip=False,
    because it runs on the browser->IdP control-plane hop where the forwarded
    client IP fluctuates.
    """
    if session.revoked_at is not None or session.stale:
        return False
    if now >= session.absolute_expires_at:
        return False
    if now - session.last_seen_at > timedelta(seconds=get_settings().idle_ttl):
        await revoke(db, session, reason="idle_timeout", source_ip=source_ip)
        return False
    if enforce_ip and str(session.source_ip) != source_ip:
        session.stale = True
        await db.flush()
        await emit(
            db,
            AuthEventType.SESSION_STALE_IP,
            source_ip=source_ip,
            success=False,
            user_id=session.user_id,
            session_id=session.id,
            detail={"old_ip": str(session.source_ip), "new_ip": source_ip},
        )
        return False
    await touch(db, session, now)
    return True


async def get_session_from_cookie(
    db: AsyncSession, cookie_value: str | None, *, source_ip: str, now: datetime
) -> Session | None:
    """Resolve and liveness-check the browser session cookie.

    Liveness is checked with enforce_ip=False: every caller is a browser->IdP
    control-plane page (authorize, oidc logout, redirect_if_authenticated,
    webauthn done/step-up), reached through the data plane, so the forwarded
    client IP the IdP observes is not stable across the hop. Pinning it here
    marks the just-issued session stale on the immediate post-login redirect and
    bounces the user back into login. Mirrors resolve_gateway_session, which
    inherits only this session's liveness/revocation for the same reason. The
    data-plane resource path (check_request) keeps IP binding.
    """
    if not cookie_value or "." not in cookie_value:
        return None
    sid_str, _, secret = cookie_value.partition(".")
    try:
        sid = uuid.UUID(sid_str)
    except ValueError:
        return None
    session = await db.get(Session, sid)
    if session is None:
        return None
    if not constant_time_equals(sha256_hex(secret), session.cookie_secret_hash):
        return None
    if not await check_liveness(db, session, source_ip=source_ip, now=now, enforce_ip=False):
        return None
    return session


async def touch(db: AsyncSession, session: Session, now: datetime) -> None:
    """Refresh the idle-timeout basis, throttled to one write per interval."""
    interval = timedelta(seconds=get_settings().session_touch_interval)
    if now - session.last_seen_at >= interval:
        session.last_seen_at = now
        await db.flush()


class RequestAuthError(Exception):
    """Any failure in check_request; maps to 401 with WWW-Authenticate: DPoP."""

    def __init__(self, error: str, detail: str) -> None:
        super().__init__(detail)
        self.error = error  # invalid_token | invalid_dpop_proof
        self.detail = detail


@dataclass(frozen=True)
class AuthedRequest:
    session: Session
    user: User
    claims: "tokens.AccessClaims"


async def check_request(
    db: AsyncSession,
    *,
    authorization: str | None,
    dpop_proof: str | None,
    htm: str,
    htu: str,
    source_ip: str,
    now: datetime,
) -> AuthedRequest:
    """The per-request resource-server check (userinfo, admin API, and the
    contract the Go data plane inherits):

    1. JWT signature (active+retiring keys), exp, iss.
    2. DPoP proof valid; proof jkt == cnf.jkt; ath matches this token.
    3. Session by sid: revoked/stale/absolute/idle all reject.
    4. Source-IP binding (marks stale on change).
    """
    from hyproxy.idp.oidc import tokens
    from hyproxy.idp.oidc.dpop import DpopError, verify_proof
    from hyproxy.idp.oidc.replay import PgJtiReplayCache

    if not authorization or not authorization.startswith("DPoP "):
        raise RequestAuthError("invalid_token", "missing DPoP authorization")
    access_token = authorization.removeprefix("DPoP ").strip()
    try:
        claims = await tokens.verify_access_token(db, token=access_token, now=now)
    except tokens.TokenError as exc:
        raise RequestAuthError("invalid_token", exc.args[0]) from exc

    if not dpop_proof:
        raise RequestAuthError("invalid_dpop_proof", "missing DPoP header")
    settings = get_settings()
    try:
        await verify_proof(
            dpop_proof,
            htm=htm,
            htu=htu,
            now=now,
            replay_cache=PgJtiReplayCache(db),
            iat_window=settings.dpop_iat_window,
            iat_future_skew=settings.dpop_iat_future_skew,
            access_token=access_token,
            expected_jkt=claims.jkt,
        )
    except DpopError as exc:
        raise RequestAuthError("invalid_dpop_proof", exc.detail) from exc

    session = await db.get(Session, claims.sid)
    if session is None:
        raise RequestAuthError("invalid_token", "unknown session")
    if not await check_liveness(db, session, source_ip=source_ip, now=now):
        raise RequestAuthError("invalid_token", "session not live")
    user = await db.get(User, session.user_id)
    if user is None or user.status != "active":
        raise RequestAuthError("invalid_token", "user not active")
    return AuthedRequest(session=session, user=user, claims=claims)


async def revoke(db: AsyncSession, session: Session, *, reason: str, source_ip: str) -> None:
    if session.revoked_at is not None:
        return
    session.revoked_at = datetime.now(UTC)
    session.revoke_reason = reason
    await db.flush()
    event = (
        AuthEventType.SESSION_IDLE_TIMEOUT
        if reason == "idle_timeout"
        else AuthEventType.SESSION_REVOKED
    )
    await emit(
        db,
        event,
        source_ip=source_ip,
        success=True,
        user_id=session.user_id,
        session_id=session.id,
        detail={"reason": reason},
    )

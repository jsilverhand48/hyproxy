"""POST /oidc/token: authorization_code + refresh_token grants, public client
with PKCE, DPoP-bound tokens.

Key defenses:
- Code replay: a consumed code presented again revokes the issuing session.
- PKCE S256 constant-time verification; plain unsupported.
- jkt continuity: the session's DPoP key is set at first exchange and
  immutable afterwards; refresh proofs must use the family's bound key.
- Refresh reuse: presenting a used token revokes the family and the session.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Form, Header, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.audit.events import AuthEventType, emit
from hyproxy.config import get_settings
from hyproxy.core import secrets
from hyproxy.db.models import OAuthClient, Session, User
from hyproxy.idp import sessions
from hyproxy.idp.oidc import codes, refresh, tokens
from hyproxy.idp.oidc.dpop import DpopError, DpopProof, verify_proof
from hyproxy.idp.oidc.replay import PgJtiReplayCache
from hyproxy.idp.web.routes import DbDep, client_ip
from hyproxy.security.pkce import verify_s256

router = APIRouter()


def _error(error: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error}, status_code=status)


def _token_htu() -> str:
    return f"{get_settings().issuer.rstrip('/')}/oidc/token"


async def _verify_dpop(db: AsyncSession, dpop: str | None, now: datetime) -> DpopProof:
    if not dpop:
        raise DpopError("missing DPoP header")
    settings = get_settings()
    return await verify_proof(
        dpop,
        htm="POST",
        htu=_token_htu(),
        now=now,
        replay_cache=PgJtiReplayCache(db),
        iat_window=settings.dpop_iat_window,
        iat_future_skew=settings.dpop_iat_future_skew,
    )


async def _live_session(
    db: AsyncSession, session_id: object, ip: str, now: datetime
) -> Session | None:
    session = await db.get(Session, session_id)
    if session is None:
        return None
    if not await sessions.check_liveness(db, session, source_ip=ip, now=now):
        return None
    return session


@router.post("/oidc/token")
async def token_endpoint(
    request: Request,
    db: DbDep,
    grant_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()] = "",
    code: Annotated[str, Form()] = "",
    redirect_uri: Annotated[str, Form()] = "",
    code_verifier: Annotated[str, Form()] = "",
    refresh_token: Annotated[str, Form()] = "",
    dpop: Annotated[str | None, Header(alias="DPoP")] = None,
) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)

    client = await db.scalar(
        select(OAuthClient).where(OAuthClient.client_id == client_id, OAuthClient.enabled.is_(True))
    )
    if client is None:
        return _error("invalid_client", 401)

    try:
        proof = await _verify_dpop(db, dpop, now)
    except DpopError:
        return _error("invalid_dpop_proof")

    if grant_type == "authorization_code":
        return await _authorization_code_grant(
            db, client, proof, code, redirect_uri, code_verifier, ip, now
        )
    if grant_type == "refresh_token":
        return await _refresh_grant(db, client, proof, refresh_token, ip, now)
    return _error("unsupported_grant_type")


async def _authorization_code_grant(
    db: AsyncSession,
    client: OAuthClient,
    proof: DpopProof,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    ip: str,
    now: datetime,
) -> Response:
    if not code or not redirect_uri or not code_verifier:
        return _error("invalid_request")

    row = await codes.consume_code(db, code, now)
    if row is None:
        replayed = await codes.find_consumed(db, code)
        if replayed is not None:
            # Replay: someone (attacker or victim) already exchanged this code.
            session = await db.get(Session, replayed.session_id)
            if session is not None:
                await refresh.revoke_for_session(db, session.id)
                await sessions.revoke(db, session, reason="auth_code_replay", source_ip=ip)
            await emit(
                db,
                AuthEventType.OIDC_CODE_REPLAY_DETECTED,
                source_ip=ip,
                success=False,
                user_id=replayed.user_id,
                session_id=replayed.session_id,
                client_id=client.client_id,
            )
        return _error("invalid_grant")

    if row.client_id != client.client_id:
        return _error("invalid_grant")
    if row.redirect_uri != redirect_uri:  # byte-exact
        return _error("invalid_grant")
    if not verify_s256(code_verifier, row.code_challenge):
        return _error("invalid_grant")

    session = await _live_session(db, row.session_id, ip, now)
    if session is None:
        return _error("invalid_grant")

    # DPoP key binding: first exchange pins the session to this key.
    if session.dpop_jkt is None:
        session.dpop_jkt = proof.jkt
        await db.flush()
    elif session.dpop_jkt != proof.jkt:
        return _error("invalid_grant")

    user = await db.get(User, session.user_id)
    if user is None or user.status != "active":
        return _error("invalid_grant")

    backend = secrets.get_secrets_backend()
    access_token = await tokens.mint_access_token(
        db,
        backend,
        user=user,
        session=session,
        client_id=client.client_id,
        scope=row.scope,
        jkt=proof.jkt,
        now=now,
    )
    id_token = await tokens.mint_id_token(
        db,
        backend,
        user=user,
        session=session,
        client_id=client.client_id,
        nonce=row.nonce,
        auth_time=row.auth_time,
        now=now,
    )
    new_refresh = await refresh.issue_family(
        db, session=session, client_id=client.client_id, scope=row.scope, jkt=proof.jkt, now=now
    )
    await emit(
        db,
        AuthEventType.OIDC_TOKEN_ISSUED,
        source_ip=ip,
        success=True,
        user_id=user.id,
        session_id=session.id,
        client_id=client.client_id,
        detail={"grant_type": "authorization_code", "scope": row.scope},
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": get_settings().access_ttl,
            "refresh_token": new_refresh,
            "id_token": id_token,
            "scope": row.scope,
        }
    )


async def _refresh_grant(
    db: AsyncSession,
    client: OAuthClient,
    proof: DpopProof,
    refresh_token: str,
    ip: str,
    now: datetime,
) -> Response:
    if not refresh_token:
        return _error("invalid_request")
    row = await refresh.find(db, refresh_token)
    if row is None or row.client_id != client.client_id:
        return _error("invalid_grant")

    if row.used_at is not None:
        # Rotation reuse: kill the whole family and the session.
        await refresh.revoke_family(db, row.family_id)
        session = await db.get(Session, row.session_id)
        if session is not None:
            await sessions.revoke(db, session, reason="refresh_reuse", source_ip=ip)
        await emit(
            db,
            AuthEventType.OIDC_REFRESH_REUSE_DETECTED,
            source_ip=ip,
            success=False,
            user_id=row.user_id,
            session_id=row.session_id,
            client_id=client.client_id,
            detail={"family_id": str(row.family_id)},
        )
        return _error("invalid_grant")

    if row.revoked_at is not None or row.expires_at <= now:
        return _error("invalid_grant")
    if row.dpop_jkt != proof.jkt:
        return _error("invalid_grant")

    session = await _live_session(db, row.session_id, ip, now)
    if session is None:
        return _error("invalid_grant")
    user = await db.get(User, session.user_id)
    if user is None or user.status != "active":
        return _error("invalid_grant")

    new_refresh = await refresh.rotate(db, row, now=now)
    backend = secrets.get_secrets_backend()
    access_token = await tokens.mint_access_token(
        db,
        backend,
        user=user,
        session=session,
        client_id=client.client_id,
        scope=row.scope,
        jkt=proof.jkt,
        now=now,
    )
    await emit(
        db,
        AuthEventType.OIDC_TOKEN_REFRESHED,
        source_ip=ip,
        success=True,
        user_id=user.id,
        session_id=session.id,
        client_id=client.client_id,
        detail={"family_id": str(row.family_id)},
    )
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": get_settings().access_ttl,
            "refresh_token": new_refresh,
            "scope": row.scope,
        }
    )

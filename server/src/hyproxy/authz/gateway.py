"""Gateway RP endpoints (browser-facing through the data plane's auth host).

/gateway/start parks a validated return URL and sends the browser to the IdP
authorize endpoint (code + PKCE, gateway client). /gateway/callback exchanges
the code with the gateway's server-side DPoP key, verifies the tokens against
the shared signing keys, links a gateway session to the IdP session (so
liveness, revocation, IP binding, and the 6h bound are all inherited), and
sends the browser back to the app.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.audit.events import AuthEventType, emit
from hyproxy.authz import gwkey
from hyproxy.config import get_settings
from hyproxy.core import secrets
from hyproxy.core.crypto import constant_time_equals, new_token, sha256_hex
from hyproxy.core.netutil import resolve_client_ip
from hyproxy.db.engine import get_db
from hyproxy.db.models import (
    GatewayLoginState,
    GatewaySession,
    Resource,
    Session,
)
from hyproxy.idp import sessions as idp_sessions
from hyproxy.idp.oidc import tokens as token_service

router = APIRouter(prefix="/gateway")

logger = logging.getLogger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]


def client_ip(request: Request) -> str:
    return resolve_client_ip(request)


async def valid_return_url(db: AsyncSession, rd: str) -> bool:
    """Open-redirect guard: only https URLs whose host is a registered,
    enabled resource public_host — or one of the configured SPA origins
    (admin console / portal, which may be static data-plane routes rather
    than DB resources) — may be returned to."""
    settings = get_settings()
    try:
        parts = urlsplit(rd)
    except ValueError:
        return False
    if parts.scheme != settings.external_scheme or not parts.hostname:
        return False
    for origin in (settings.admin_ui_origin, settings.portal_origin):
        if origin and urlsplit(origin).hostname == parts.hostname:
            return True
    resource = await db.scalar(
        select(Resource).where(Resource.public_host == parts.hostname, Resource.enabled.is_(True))
    )
    return resource is not None


@router.get("/start")
async def start(request: Request, db: DbDep, rd: str = "") -> Response:
    settings = get_settings()
    now = datetime.now(UTC)
    if not rd or not await valid_return_url(db, rd):
        return PlainTextResponse("invalid return URL", status_code=400)

    state = new_token(24)
    verifier = new_token(48)
    nonce = new_token(24)
    db.add(
        GatewayLoginState(
            state_hash=sha256_hex(state),
            code_verifier=verifier,
            nonce=nonce,
            return_url=rd,
            source_ip=client_ip(request),
            expires_at=now + timedelta(seconds=settings.gateway_state_ttl),
        )
    )
    await db.flush()

    from hyproxy.core.crypto import sha256_b64url

    params = {
        "client_id": settings.gateway_client_id,
        "redirect_uri": gateway_redirect_uri(),
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": sha256_b64url(verifier),
        "code_challenge_method": "S256",
    }
    return RedirectResponse(
        f"{settings.issuer.rstrip('/')}/oidc/authorize?{urlencode(params)}", status_code=303
    )


def gateway_redirect_uri() -> str:
    settings = get_settings()
    return f"{settings.external_scheme}://{settings.auth_host}/gateway/callback"


@router.get("/callback")
async def callback(
    request: Request,
    db: DbDep,
    code: str = "",
    state: str = "",
    error: str = "",
) -> Response:
    settings = get_settings()
    now = datetime.now(UTC)
    ip = client_ip(request)
    if error:
        return PlainTextResponse(f"sign-in failed: {error}", status_code=400)
    if not code or not state:
        return PlainTextResponse("missing code or state", status_code=400)

    row = await db.get(GatewayLoginState, sha256_hex(state))
    if row is None or row.expires_at <= now or str(row.source_ip) != ip:
        return PlainTextResponse("sign-in expired, start over", status_code=400)
    return_url, verifier, nonce = row.return_url, row.code_verifier, row.nonce
    await db.delete(row)  # single use
    await db.flush()

    key = gwkey.gateway_dpop_key(secrets.get_secrets_backend())
    issuer = settings.issuer.rstrip("/")
    idp_http: httpx.AsyncClient = request.app.state.idp_http
    try:
        token_resp = await idp_http.post(
            "/oidc/token",
            data={
                "grant_type": "authorization_code",
                "client_id": settings.gateway_client_id,
                "code": code,
                "redirect_uri": gateway_redirect_uri(),
                "code_verifier": verifier,
            },
            headers={"DPoP": gwkey.make_proof(key, "POST", f"{issuer}/oidc/token")},
        )
    except httpx.HTTPError:
        # Backchannel to the IdP is unreachable (DNS/TLS/timeout). Fail with a
        # retryable status instead of an opaque 500, and leave a trace to debug.
        logger.exception("gateway token backchannel to IdP failed (base_url=%s)", idp_http.base_url)
        return PlainTextResponse("sign-in temporarily unavailable, try again", status_code=502)
    if token_resp.status_code != 200:
        return PlainTextResponse("sign-in failed, start over", status_code=400)

    try:
        body = token_resp.json()
        access = await token_service.verify_access_token(db, token=body["access_token"], now=now)
        id_claims = await token_service.verify_id_token(
            db, token=body["id_token"], client_id=settings.gateway_client_id, now=now
        )
    except (token_service.TokenError, KeyError, ValueError):
        return PlainTextResponse("sign-in failed, start over", status_code=400)
    if id_claims.get("nonce") != nonce:
        return PlainTextResponse("sign-in failed, start over", status_code=400)

    idp_session = await db.get(Session, access.sid)
    if idp_session is None:
        return PlainTextResponse("sign-in failed, start over", status_code=400)

    secret = new_token(32)
    gw = GatewaySession(
        user_id=idp_session.user_id,
        idp_session_id=idp_session.id,
        cookie_secret_hash=sha256_hex(secret),
        source_ip=ip,
    )
    db.add(gw)
    await db.flush()
    await emit(
        db,
        AuthEventType.SESSION_CREATED,
        source_ip=ip,
        success=True,
        user_id=idp_session.user_id,
        session_id=idp_session.id,
        client_id=settings.gateway_client_id,
        detail={"stage": "gateway"},
    )

    resp = RedirectResponse(return_url, status_code=303)
    set_gateway_cookie(resp, f"{gw.id}.{secret}")
    return resp


def set_gateway_cookie(response: Response, value: str) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.gateway_cookie_name,
        value,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        domain=settings.gateway_cookie_domain or None,
        max_age=get_settings().refresh_abs_ttl,
    )


async def resolve_gateway_session(
    db: AsyncSession, cookie_value: str | None, *, source_ip: str, now: datetime
) -> GatewaySession | None:
    """Gateway cookie -> live gateway session with a live IdP session behind it."""
    if not cookie_value or "." not in cookie_value:
        return None
    gw_id_str, _, secret = cookie_value.partition(".")
    try:
        gw_id = uuid.UUID(gw_id_str)
    except ValueError:
        return None
    gw = await db.get(GatewaySession, gw_id)
    if gw is None or gw.revoked_at is not None:
        return None
    if not constant_time_equals(sha256_hex(secret), gw.cookie_secret_hash):
        return None
    # IP-bind against the gateway session's own origin. Both this value (set at
    # /gateway/callback) and the source_ip on every caller are observed at the
    # data plane, the single ingress, so they agree. The IdP session is bound to
    # the separate browser->IdP hop, whose vantage point need not resolve to the
    # same client IP, so inherit only its liveness/revocation here
    # (enforce_ip=False) rather than tripping a spurious re-auth loop on the
    # cross-plane IP mismatch.
    if str(gw.source_ip) != source_ip:
        return None
    idp_session = await db.get(Session, gw.idp_session_id)
    if idp_session is None:
        return None
    if not await idp_sessions.check_liveness(
        db, idp_session, source_ip=source_ip, now=now, enforce_ip=False
    ):
        return None
    return gw


@router.get("/logout")
async def logout(request: Request, db: DbDep) -> Response:
    settings = get_settings()
    now = datetime.now(UTC)
    ip = client_ip(request)
    gw = await resolve_gateway_session(
        db, request.cookies.get(settings.gateway_cookie_name), source_ip=ip, now=now
    )
    if gw is not None:
        gw.revoked_at = now
        await db.flush()
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(
        settings.gateway_cookie_name,
        path="/",
        domain=settings.gateway_cookie_domain or None,
    )
    return resp


async def gc_login_states(db: AsyncSession, now: datetime) -> int:
    result = await db.execute(delete(GatewayLoginState).where(GatewayLoginState.expires_at <= now))
    return int(getattr(result, "rowcount", 0) or 0)

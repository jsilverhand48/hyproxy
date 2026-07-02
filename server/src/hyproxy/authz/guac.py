"""Guacamole tunnel-token endpoint (browser-facing through the data plane's
auth host, like /gateway/*). An end user with a live gateway session asks for a
tunnel token for a resource; the broker policy-checks, mints a short-lived
single-use guacamole-lite token, and audits. Internal service: only the auth
host's /guac/* paths are proxied here by the data plane.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.authz.gateway import client_ip, resolve_gateway_session
from hyproxy.config import get_settings
from hyproxy.core import secrets
from hyproxy.db.engine import get_db
from hyproxy.guac import broker

router = APIRouter(prefix="/guac")

DbDep = Annotated[AsyncSession, Depends(get_db)]


class TokenRequest(BaseModel):
    resource_id: uuid.UUID


class ConsumeRequest(BaseModel):
    token: str
    source_ip: str | None = None  # the browser IP, forwarded by the data plane
    gateway_cookie: str | None = None


@router.post("/token")
async def guac_token(body: TokenRequest, request: Request, db: DbDep) -> Response:
    settings = get_settings()
    now = datetime.now(UTC)
    ip = client_ip(request)
    gw = await resolve_gateway_session(
        db, request.cookies.get(settings.gateway_cookie_name), source_ip=ip, now=now
    )
    if gw is None:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    result = await broker.issue_tunnel(
        db,
        secrets.get_secrets_backend(),
        user_id=gw.user_id,
        resource_id=body.resource_id,
        source_ip=ip,
        now=now,
    )
    if not result.allowed:
        status = 503 if result.reason == "guac_disabled" else 403
        return JSONResponse({"error": result.reason}, status_code=status)
    assert result.token is not None and result.expires_at is not None
    return JSONResponse(
        {
            "token": result.token,
            "protocol": result.protocol,
            "expires_at": result.expires_at.isoformat(),
        }
    )


@router.post("/consume")
async def guac_consume(body: ConsumeRequest, request: Request, db: DbDep) -> Response:
    """Called by the data plane when it forward-auths a tunnel WebSocket connect.

    Ties the connect to a LIVE gateway session (so revoking the IdP session tears
    the tunnel down) and single-use-consumes the grant, IP-bound. Returns allow
    exactly once per minted token."""
    settings = get_settings()
    now = datetime.now(UTC)
    ip = body.source_ip or client_ip(request)
    gw = await resolve_gateway_session(
        db, body.gateway_cookie or request.cookies.get(settings.gateway_cookie_name),
        source_ip=ip, now=now,
    )
    if gw is None:
        return JSONResponse({"decision": "deny", "reason": "auth_required"}, status_code=401)
    ok = await broker.consume_grant(
        db, body.token, source_ip=ip, now=now, user_id=gw.user_id
    )
    if not ok:
        return JSONResponse({"decision": "deny", "reason": "invalid_grant"}, status_code=403)
    return JSONResponse({"decision": "allow"})

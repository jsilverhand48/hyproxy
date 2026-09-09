"""RTSP stream-token endpoint (browser-facing through the data plane's auth
host, like /gateway/* and /guac/token). An end user with a live gateway session
posts the camera's own username and password for a resource; the broker
policy-checks, mints a short-lived single-use token carrying the resolved RTSP
URL, and audits. Internal service: only the auth host's /rtsp/token is proxied
here by the data plane, never /rtsp/consume.

The camera credentials in the request body are the SECOND authentication factor
for the backend, not for hyproxy. They are never stored: they go straight into
the encrypted token and are dropped.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.authz.gateway import client_ip, resolve_gateway_session
from hyproxy.config import get_settings
from hyproxy.db.engine import get_db
from hyproxy.rtsp import broker

router = APIRouter(prefix="/rtsp")

DbDep = Annotated[AsyncSession, Depends(get_db)]


class TokenRequest(BaseModel):
    resource_id: uuid.UUID
    # The camera's own credentials, supplied by the viewer per session.
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=255)


class ConsumeRequest(BaseModel):
    token: str
    source_ip: str | None = None  # the browser IP, forwarded by the data plane
    gateway_cookie: str | None = None


@router.post("/token")
async def rtsp_token(body: TokenRequest, request: Request, db: DbDep) -> Response:
    settings = get_settings()
    now = datetime.now(UTC)
    ip = client_ip(request)
    # enforce_ip=False: the mint and the stream WebSocket are separate
    # connections to separate hosts, and a phone's egress address routinely
    # differs between them. The grant this issues is still IP-bound, single-use
    # and short-lived, so the stream authorization keeps its own binding.
    gw = await resolve_gateway_session(
        db,
        request.cookies.get(settings.gateway_cookie_name),
        source_ip=ip,
        now=now,
        enforce_ip=False,
    )
    if gw is None:
        return JSONResponse({"error": "auth_required"}, status_code=401)

    result = await broker.issue_stream(
        db,
        user_id=gw.user_id,
        resource_id=body.resource_id,
        rtsp_username=body.username,
        rtsp_password=body.password,
        source_ip=ip,
        now=now,
    )
    if not result.allowed:
        status = 503 if result.reason == "rtsp_disabled" else 403
        return JSONResponse({"error": result.reason}, status_code=status)
    assert result.token is not None and result.expires_at is not None
    return JSONResponse({"token": result.token, "expires_at": result.expires_at.isoformat()})


@router.post("/consume")
async def rtsp_consume(body: ConsumeRequest, request: Request, db: DbDep) -> Response:
    """Called by the data plane when it forward-auths a stream WebSocket connect.

    Ties the connect to a LIVE gateway session (so revoking the IdP session stops
    the stream from being reopened) and single-use-consumes the grant, IP-bound.
    Returns allow exactly once per minted token."""
    settings = get_settings()
    now = datetime.now(UTC)
    ip = body.source_ip or client_ip(request)
    # enforce_ip=False for the same reason as /token; consume_grant below still
    # requires the grant's own IP match, so the token cannot be replayed from
    # another address.
    gw = await resolve_gateway_session(
        db,
        body.gateway_cookie or request.cookies.get(settings.gateway_cookie_name),
        source_ip=ip,
        now=now,
        enforce_ip=False,
    )
    if gw is None:
        return JSONResponse({"decision": "deny", "reason": "auth_required"}, status_code=401)
    ok = await broker.consume_grant(db, body.token, source_ip=ip, now=now, user_id=gw.user_id)
    if not ok:
        return JSONResponse({"decision": "deny", "reason": "invalid_grant"}, status_code=403)
    return JSONResponse({"decision": "allow"})

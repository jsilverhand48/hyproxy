"""GET /oidc/userinfo: DPoP-bound resource endpoint, claims filtered by scope."""

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, Response

from hyproxy.config import get_settings
from hyproxy.idp import sessions
from hyproxy.idp.web.routes import DbDep, client_ip

router = APIRouter()


def unauthorized(error: str) -> JSONResponse:
    resp = JSONResponse({"error": error}, status_code=401)
    resp.headers["WWW-Authenticate"] = f'DPoP error="{error}", algs="ES256"'
    return resp


@router.get("/oidc/userinfo")
async def userinfo(
    request: Request,
    db: DbDep,
    authorization: Annotated[str | None, Header()] = None,
    dpop: Annotated[str | None, Header(alias="DPoP")] = None,
) -> Response:
    now = datetime.now(UTC)
    htu = f"{get_settings().issuer.rstrip('/')}/oidc/userinfo"
    try:
        authed = await sessions.check_request(
            db,
            authorization=authorization,
            dpop_proof=dpop,
            htm="GET",
            htu=htu,
            source_ip=client_ip(request),
            now=now,
        )
    except sessions.RequestAuthError as exc:
        return unauthorized(exc.error)

    scopes = set(authed.claims.scope.split())
    claims: dict[str, Any] = {"sub": authed.user.external_id}
    if "email" in scopes:
        claims["email"] = authed.user.email
    if "profile" in scopes:
        claims["name"] = authed.user.display_name
        claims["auth_tier"] = authed.session.auth_tier
    return JSONResponse(claims)

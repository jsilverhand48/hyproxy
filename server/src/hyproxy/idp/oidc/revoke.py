"""POST /oidc/revoke (RFC 7009): revokes a refresh token's family and session.

Always returns 200 for unknown tokens per the RFC. A valid DPoP proof bound
to the token's key is required, so a third party who merely leaked the token
string cannot use revocation as a denial-of-service primitive.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Form, Header, Request
from fastapi.responses import JSONResponse, Response

from hyproxy.audit.events import AuthEventType, emit
from hyproxy.config import get_settings
from hyproxy.db.models import Session
from hyproxy.idp import sessions
from hyproxy.idp.oidc import refresh
from hyproxy.idp.oidc.dpop import DpopError, verify_proof
from hyproxy.idp.oidc.replay import PgJtiReplayCache
from hyproxy.idp.web.routes import DbDep, client_ip

router = APIRouter()


@router.post("/oidc/revoke")
async def revoke_endpoint(
    request: Request,
    db: DbDep,
    token: Annotated[str, Form()],
    token_type_hint: Annotated[str | None, Form()] = None,
    dpop: Annotated[str | None, Header(alias="DPoP")] = None,
) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    settings = get_settings()
    if not dpop:
        return JSONResponse({"error": "invalid_dpop_proof"}, status_code=400)
    try:
        proof = await verify_proof(
            dpop,
            htm="POST",
            htu=f"{settings.issuer.rstrip('/')}/oidc/revoke",
            now=now,
            replay_cache=PgJtiReplayCache(db),
            iat_window=settings.dpop_iat_window,
            iat_future_skew=settings.dpop_iat_future_skew,
        )
    except DpopError:
        return JSONResponse({"error": "invalid_dpop_proof"}, status_code=400)

    row = await refresh.find(db, token)
    # RFC 7009: unknown token still returns 200. Wrong-key proofs also return
    # 200 to avoid becoming a validity oracle for stolen token strings.
    if row is not None and row.dpop_jkt == proof.jkt:
        await refresh.revoke_family(db, row.family_id)
        session = await db.get(Session, row.session_id)
        if session is not None:
            await sessions.revoke(db, session, reason="revoked_by_client", source_ip=ip)
        await emit(
            db,
            AuthEventType.OIDC_TOKEN_REVOKED,
            source_ip=ip,
            success=True,
            user_id=row.user_id,
            session_id=row.session_id,
            client_id=row.client_id,
            detail={"family_id": str(row.family_id)},
        )
    return JSONResponse({})

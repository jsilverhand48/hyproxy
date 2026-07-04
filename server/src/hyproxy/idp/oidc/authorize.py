"""GET /oidc/authorize. The validation order is load-bearing:

1. client_id must resolve to an enabled client, else a LOCAL error page.
2. redirect_uri must byte-exactly match a registered URI, else a LOCAL error
   page. Never redirect to an unvalidated URI.
3. Only after 1+2 may errors be returned via redirect (error + state).
4. Without a live IdP session, the validated request is parked in a login
   flow and the browser goes to /auth/login.
5. With a live session, a single-use 60s code is issued.
"""

from datetime import UTC, datetime
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from hyproxy.audit.events import AuthEventType, emit
from hyproxy.db.models import OAuthClient
from hyproxy.idp import flows as flow_service
from hyproxy.idp import sessions
from hyproxy.idp.oidc import codes
from hyproxy.idp.web.routes import DbDep, client_ip, error_page
from hyproxy.security.pkce import valid_challenge

router = APIRouter()

STATE_MIN, STATE_MAX = 16, 512


def _redirect_error(
    redirect_uri: str, error: str, state: str | None, description: str | None = None
) -> RedirectResponse:
    params = {"error": error}
    if description:
        params["error_description"] = description
    if state:
        params["state"] = state
    return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)


@router.get("/oidc/authorize")
async def authorize(request: Request, db: DbDep) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    q = request.query_params

    # 1. client_id: failure renders locally, never redirects.
    client_id = q.get("client_id")
    client: OAuthClient | None = None
    if client_id:
        client = await db.scalar(
            select(OAuthClient).where(
                OAuthClient.client_id == client_id, OAuthClient.enabled.is_(True)
            )
        )
    if client is None:
        return error_page(request, "Unknown application.", 400)

    # 2. redirect_uri: byte-exact member of the registered set, or local error.
    redirect_uri = q.get("redirect_uri")
    if not redirect_uri or redirect_uri not in client.redirect_uris:
        return error_page(request, "Invalid redirect URI for this application.", 400)

    # 3. From here, errors go back to the (validated) redirect_uri.
    state = q.get("state")
    valid_state = state is not None and STATE_MIN <= len(state) <= STATE_MAX
    if not valid_state:
        # state is also our CSRF layer for the RP; refuse without it.
        return _redirect_error(redirect_uri, "invalid_request", None, "state required")
    assert state is not None

    if q.get("response_type") != "code":
        return _redirect_error(redirect_uri, "unsupported_response_type", state)

    scope = q.get("scope", "")
    scopes = scope.split()
    if "openid" not in scopes or not set(scopes) <= set(client.allowed_scopes):
        return _redirect_error(redirect_uri, "invalid_scope", state)

    nonce = q.get("nonce")
    if not nonce or len(nonce) > 512:
        return _redirect_error(redirect_uri, "invalid_request", state, "nonce required")

    if q.get("code_challenge_method") != "S256":
        return _redirect_error(
            redirect_uri, "invalid_request", state, "code_challenge_method must be S256"
        )
    code_challenge = q.get("code_challenge")
    if not code_challenge or not valid_challenge(code_challenge):
        return _redirect_error(redirect_uri, "invalid_request", state, "invalid code_challenge")

    # 4. Need a live session?
    session = await sessions.get_session_from_cookie(
        db, request.cookies.get(sessions.SESSION_COOKIE), source_ip=ip, now=now
    )
    if session is None:
        oidc_request = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        flow, _csrf = await flow_service.create_flow(
            db, source_ip=ip, oidc_request=oidc_request, now=now
        )
        resp = RedirectResponse(f"/auth/login?flow={flow.id}", status_code=303)
        from hyproxy.idp.web.routes import set_flow_cookie

        set_flow_cookie(resp, str(flow.id))
        return resp

    # 5. Issue the code.
    code = await codes.issue_code(
        db,
        session=session,
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        nonce=nonce,
        code_challenge=code_challenge,
        now=now,
    )
    await emit(
        db,
        AuthEventType.OIDC_CODE_ISSUED,
        source_ip=ip,
        success=True,
        user_id=session.user_id,
        session_id=session.id,
        client_id=client.client_id,
        detail={"scope": scope},
    )
    return RedirectResponse(
        f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=302
    )


@router.get("/oidc/logout")
async def logout(request: Request, db: DbDep) -> Response:
    """RP-initiated logout: revoke the IdP session and clear its cookie so the
    next /oidc/authorize can no longer silently re-issue a code."""
    now = datetime.now(UTC)
    ip = client_ip(request)
    session = await sessions.get_session_from_cookie(
        db, request.cookies.get(sessions.SESSION_COOKIE), source_ip=ip, now=now
    )
    if session is not None:
        await sessions.revoke(db, session, reason="logout", source_ip=ip)

    # Only redirect to a post-logout URI whose origin matches a registered
    # redirect_uri of the named client; never redirect to an unvalidated URI.
    target = "/auth/login"
    client_id = request.query_params.get("client_id")
    requested = request.query_params.get("post_logout_redirect_uri")
    if client_id and requested:
        client = await db.scalar(
            select(OAuthClient).where(
                OAuthClient.client_id == client_id, OAuthClient.enabled.is_(True)
            )
        )
        if client is not None:
            want = urlsplit(requested)
            allowed = {(urlsplit(u).scheme, urlsplit(u).netloc) for u in client.redirect_uris}
            if (want.scheme, want.netloc) in allowed:
                target = requested

    resp = RedirectResponse(target, status_code=303)
    sessions.clear_session_cookie(resp)
    return resp

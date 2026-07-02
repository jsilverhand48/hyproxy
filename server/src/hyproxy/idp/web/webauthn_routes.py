"""WebAuthn login, bootstrap enrollment, and step-up assertion endpoints.

Security invariants:
- The assertion is the ONLY way an admin completes login; there is no TOTP
  fallback for admin-tier users anywhere.
- In-flow credential enrollment is a bootstrap path: allowed only when the
  user has no credentials that predate this login flow. Anything else would
  let a password-only attacker register their own authenticator.
- Step-up requires a fresh assertion on an already-authenticated session.
"""

import base64
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)

from hyproxy.audit.events import AuthEventType, emit
from hyproxy.config import get_settings
from hyproxy.db.models import LoginFlow, User, WebAuthnCredential
from hyproxy.idp import flows as flow_service
from hyproxy.idp import sessions
from hyproxy.idp.web.routes import (
    FLOW_COOKIE,
    DbDep,
    client_ip,
    error_page,
    finalize_login,
    flow_user,
    get_stage_flow,
    second_factor_throttle,
    templates,
)
from hyproxy.security import ratelimit
from hyproxy.security import webauthn as webauthn_service

router = APIRouter(prefix="/auth")


class FlowBody(BaseModel):
    flow: str
    csrf_token: str


class AssertionBody(FlowBody):
    credential: dict[str, Any]


class EnrollBody(FlowBody):
    credential: dict[str, Any]
    friendly_name: str = Field(min_length=1, max_length=64)
    break_glass: bool = False


class StepupVerifyBody(BaseModel):
    credential: dict[str, Any]


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _credential_id_from_response(credential: dict[str, Any]) -> bytes | None:
    raw_id = credential.get("rawId") or credential.get("id")
    if not isinstance(raw_id, str):
        return None
    try:
        padded = raw_id + "=" * (-len(raw_id) % 4)
        return base64.urlsafe_b64decode(padded)
    except ValueError:
        return None


async def _user_credentials(db: AsyncSession, user: User) -> list[WebAuthnCredential]:
    rows = await db.scalars(
        select(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == user.id)
        .order_by(WebAuthnCredential.created_at)
    )
    return list(rows)


async def _guarded_flow(
    request: Request, db: AsyncSession, body: FlowBody
) -> tuple[LoginFlow, User] | JSONResponse:
    flow_row = await get_stage_flow(request, db, body.flow, "webauthn")
    if flow_row is None or not flow_service.verify_flow_csrf(flow_row, body.csrf_token):
        return _json_error("invalid or expired sign-in flow", 400)
    user = await flow_user(db, flow_row)
    if user is None:
        return _json_error("invalid or expired sign-in flow", 400)
    return flow_row, user


def _bootstrap_enroll_allowed(creds: list[WebAuthnCredential], flow_row: LoginFlow) -> bool:
    """Enrollment during login only while no credential predates this flow."""
    return all(cred.created_at >= flow_row.created_at for cred in creds)


# --- Login assertion ---------------------------------------------------------


@router.get("/webauthn")
async def webauthn_page(request: Request, db: DbDep, flow: str | None = None) -> Response:
    flow_row = await get_stage_flow(request, db, flow, "webauthn")
    if flow_row is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    user = await flow_user(db, flow_row)
    if user is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    if not await _user_credentials(db, user):
        return RedirectResponse(f"/auth/enroll/webauthn?flow={flow_row.id}", status_code=303)
    csrf_token = await flow_service.rotate_csrf(db, flow_row)
    return templates.TemplateResponse(
        request,
        "webauthn.html",
        {"flow_id": str(flow_row.id), "csrf_token": csrf_token},
    )


@router.post("/webauthn/options")
async def webauthn_options(request: Request, db: DbDep, body: FlowBody) -> Response:
    guarded = await _guarded_flow(request, db, body)
    if isinstance(guarded, JSONResponse):
        return guarded
    flow_row, user = guarded
    creds = await _user_credentials(db, user)
    if not creds:
        return _json_error("no credentials enrolled", 400)
    options_json, challenge = webauthn_service.authentication_options_json(creds)
    flow_row.webauthn_challenge = challenge
    await db.flush()
    return JSONResponse(json.loads(options_json))


@router.post("/webauthn/verify")
async def webauthn_verify(request: Request, db: DbDep, body: AssertionBody) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    guarded = await _guarded_flow(request, db, body)
    if isinstance(guarded, JSONResponse):
        return guarded
    flow_row, user = guarded
    throttled = await second_factor_throttle(request, db, user)
    if throttled is not None:
        return _json_error("too many attempts", 429)
    challenge = flow_row.webauthn_challenge
    flow_row.webauthn_challenge = None  # single use
    await db.flush()
    if challenge is None:
        return _json_error("no assertion in progress", 400)

    cred_id = _credential_id_from_response(body.credential)
    row = (
        await db.scalar(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id)
        )
        if cred_id
        else None
    )
    if row is None or row.user_id != user.id:
        await ratelimit.register_failure(db, source_ip=ip, account_key=user.email, now=now)
        await emit(
            db, AuthEventType.LOGIN_WEBAUTHN_FAILURE, source_ip=ip, success=False, user_id=user.id
        )
        return _json_error("verification failed", 401)

    try:
        new_count = webauthn_service.verify_assertion(json.dumps(body.credential), challenge, row)
    except InvalidAuthenticationResponse:
        await ratelimit.register_failure(db, source_ip=ip, account_key=user.email, now=now)
        await emit(
            db, AuthEventType.LOGIN_WEBAUTHN_FAILURE, source_ip=ip, success=False, user_id=user.id
        )
        return _json_error("verification failed", 401)

    row.sign_count = new_count
    row.last_used_at = now
    await db.flush()
    await ratelimit.reset_account(db, user.email)
    await emit(
        db,
        AuthEventType.LOGIN_WEBAUTHN_SUCCESS,
        source_ip=ip,
        success=True,
        user_id=user.id,
        detail={"friendly_name": row.friendly_name},
    )
    if row.break_glass:
        await emit(
            db,
            AuthEventType.LOGIN_BREAK_GLASS_USED,
            source_ip=ip,
            success=True,
            user_id=user.id,
            detail={"friendly_name": row.friendly_name},
        )

    cookie_value, continue_url = await finalize_login(db, flow_row, user, ["pwd", "webauthn"], ip)
    resp = JSONResponse({"redirect": continue_url or "/auth/done"})
    sessions.set_session_cookie(resp, cookie_value)
    resp.delete_cookie(FLOW_COOKIE, path="/")
    return resp


@router.get("/done")
async def done_page(request: Request, db: DbDep) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    session = await sessions.get_session_from_cookie(
        db, request.cookies.get(sessions.SESSION_COOKIE), source_ip=ip, now=now
    )
    if session is None:
        return RedirectResponse("/auth/login", status_code=303)
    user = await db.get(User, session.user_id)
    return templates.TemplateResponse(request, "signedin.html", {"user": user})


# --- Bootstrap enrollment (during login, zero pre-existing credentials) ------


@router.get("/enroll/webauthn")
async def enroll_webauthn_page(request: Request, db: DbDep, flow: str | None = None) -> Response:
    flow_row = await get_stage_flow(request, db, flow, "webauthn")
    if flow_row is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    user = await flow_user(db, flow_row)
    if user is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    creds = await _user_credentials(db, user)
    if not _bootstrap_enroll_allowed(creds, flow_row):
        return error_page(request, "Passkeys are already enrolled. Sign in with your passkey.", 403)
    csrf_token = await flow_service.rotate_csrf(db, flow_row)
    return templates.TemplateResponse(
        request,
        "enroll_webauthn.html",
        {
            "flow_id": str(flow_row.id),
            "csrf_token": csrf_token,
            "enrolled": len(creds),
        },
    )


@router.post("/enroll/webauthn/options")
async def enroll_webauthn_options(request: Request, db: DbDep, body: FlowBody) -> Response:
    guarded = await _guarded_flow(request, db, body)
    if isinstance(guarded, JSONResponse):
        return guarded
    flow_row, user = guarded
    creds = await _user_credentials(db, user)
    if not _bootstrap_enroll_allowed(creds, flow_row):
        return _json_error("enrollment not allowed", 403)
    options_json, challenge = webauthn_service.registration_options_json(user, creds)
    flow_row.webauthn_challenge = challenge
    await db.flush()
    return JSONResponse(json.loads(options_json))


@router.post("/enroll/webauthn/verify")
async def enroll_webauthn_verify(request: Request, db: DbDep, body: EnrollBody) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    guarded = await _guarded_flow(request, db, body)
    if isinstance(guarded, JSONResponse):
        return guarded
    flow_row, user = guarded
    creds = await _user_credentials(db, user)
    if not _bootstrap_enroll_allowed(creds, flow_row):
        return _json_error("enrollment not allowed", 403)
    challenge = flow_row.webauthn_challenge
    flow_row.webauthn_challenge = None
    await db.flush()
    if challenge is None:
        return _json_error("no enrollment in progress", 400)

    try:
        result = webauthn_service.verify_registration(json.dumps(body.credential), challenge)
    except InvalidRegistrationResponse:
        await emit(db, AuthEventType.ENROLL_WEBAUTHN, source_ip=ip, success=False, user_id=user.id)
        return _json_error("registration failed", 400)

    db.add(
        WebAuthnCredential(
            user_id=user.id,
            credential_id=result.credential_id,
            public_key=result.public_key,
            sign_count=result.sign_count,
            aaguid=result.aaguid,
            friendly_name=body.friendly_name,
            break_glass=body.break_glass,
            created_at=now,
        )
    )
    await db.flush()
    await emit(
        db,
        AuthEventType.ENROLL_WEBAUTHN,
        source_ip=ip,
        success=True,
        user_id=user.id,
        detail={"friendly_name": body.friendly_name},
    )
    return JSONResponse({"enrolled": len(creds) + 1})


# --- Step-up (fresh assertion on a live session) ------------------------------


def valid_stepup_return(return_to: str) -> bool:
    """The post-step-up target must be the configured admin-UI origin exactly.

    Open-redirect defense identical in spirit to the gateway's return-URL check:
    scheme + host + port must equal admin_ui_origin, no userinfo, no scheme
    smuggling. Empty admin_ui_origin means no admin UI is wired, so nothing is a
    valid target."""
    origin = get_settings().admin_ui_origin
    if not origin or not return_to:
        return False
    parts = urlsplit(return_to)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username:
        return False
    return f"{parts.scheme}://{parts.netloc}" == origin


@router.get("/stepup")
async def stepup_page(request: Request, db: DbDep, return_to: str = "") -> Response:
    """Top-level page the admin SPA navigates to for a fresh WebAuthn step-up.

    A full-page navigation (not an XHR) so the SameSite=Lax IdP session cookie
    rides along; the SPA cannot carry it on a cross-origin fetch. On success the
    page redirects back to the validated admin-UI origin."""
    if not valid_stepup_return(return_to):
        return error_page(request, "Invalid step-up request.", status=400)
    now = datetime.now(UTC)
    session = await sessions.get_session_from_cookie(
        db, request.cookies.get(sessions.SESSION_COOKIE), source_ip=client_ip(request), now=now
    )
    if session is None:
        return error_page(request, "Your session expired. Please sign in again.", status=401)
    user = await db.get(User, session.user_id)
    if user is None or user.auth_tier != "admin":
        return error_page(request, "Step-up requires an admin passkey.", status=403)
    return templates.TemplateResponse(request, "stepup.html", {"return_to": return_to})


@router.post("/stepup/options")
async def stepup_options(request: Request, db: DbDep) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    session = await sessions.get_session_from_cookie(
        db, request.cookies.get(sessions.SESSION_COOKIE), source_ip=ip, now=now
    )
    if session is None:
        return _json_error("not signed in", 401)
    user = await db.get(User, session.user_id)
    if user is None or user.auth_tier != "admin":
        return _json_error("step-up requires an admin passkey", 403)
    creds = (
        await db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))
    ).all()
    if not creds:
        return _json_error("no credentials enrolled", 400)
    options_json, challenge = webauthn_service.authentication_options_json(list(creds))
    session.stepup_challenge = challenge
    await db.flush()
    return JSONResponse(json.loads(options_json))


@router.post("/stepup/verify")
async def stepup_verify(request: Request, db: DbDep, body: StepupVerifyBody) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    session = await sessions.get_session_from_cookie(
        db, request.cookies.get(sessions.SESSION_COOKIE), source_ip=ip, now=now
    )
    if session is None:
        return _json_error("not signed in", 401)
    user = await db.get(User, session.user_id)
    if user is None or user.auth_tier != "admin":
        return _json_error("step-up requires an admin passkey", 403)
    challenge = session.stepup_challenge
    session.stepup_challenge = None
    await db.flush()
    if challenge is None:
        return _json_error("no step-up in progress", 400)

    cred_id = _credential_id_from_response(body.credential)
    row = (
        await db.scalar(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id)
        )
        if cred_id
        else None
    )
    if row is None or row.user_id != user.id:
        await emit(db, AuthEventType.STEPUP_FAILURE, source_ip=ip, success=False, user_id=user.id)
        return _json_error("verification failed", 401)
    try:
        new_count = webauthn_service.verify_assertion(json.dumps(body.credential), challenge, row)
    except InvalidAuthenticationResponse:
        await emit(db, AuthEventType.STEPUP_FAILURE, source_ip=ip, success=False, user_id=user.id)
        return _json_error("verification failed", 401)

    row.sign_count = new_count
    row.last_used_at = now
    session.step_up_verified_at = now
    await db.flush()
    await emit(
        db,
        AuthEventType.STEPUP_SUCCESS,
        source_ip=ip,
        success=True,
        user_id=user.id,
        session_id=session.id,
    )
    return JSONResponse({"ok": True})

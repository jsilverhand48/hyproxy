from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.audit.events import AuthEventType, emit
from hyproxy.core.netutil import resolve_client_ip
from hyproxy.core.secrets import get_secrets_backend
from hyproxy.db.engine import get_db
from hyproxy.db.models import LoginFlow, Session, User
from hyproxy.idp import flows as flow_service
from hyproxy.idp import sessions
from hyproxy.security import passwords, ratelimit
from hyproxy.security import recovery as recovery_service
from hyproxy.security import totp as totp_service

router = APIRouter(prefix="/auth")

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

FLOW_COOKIE = "__Host-login_flow"

DbDep = Annotated[AsyncSession, Depends(get_db)]


def client_ip(request: Request) -> str:
    return resolve_client_ip(request)


def set_flow_cookie(response: Response, flow_id: str) -> None:
    response.set_cookie(FLOW_COOKIE, flow_id, httponly=True, secure=True, samesite="lax", path="/")


def _login_page(
    request: Request, flow_id: str, csrf_token: str, error: str | None = None, status: int = 200
) -> HTMLResponse:
    resp = templates.TemplateResponse(
        request,
        "login.html",
        {"flow_id": flow_id, "csrf_token": csrf_token, "error": error},
        status_code=status,
    )
    set_flow_cookie(resp, flow_id)
    return resp


def error_page(request: Request, message: str, status: int = 400) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "error.html", {"message": message}, status_code=status
    )


@router.get("/login")
async def login_form(request: Request, db: DbDep, flow: str | None = None) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    existing = await flow_service.get_valid_flow(db, flow, source_ip=ip, now=now)
    if existing is not None and existing.stage != "password":
        # Refuse to restart a flow mid-way; force a clean start.
        await flow_service.delete_flow(db, existing)
        existing = None
    if existing is None:
        new_flow, csrf_token = await flow_service.create_flow(
            db, source_ip=ip, oidc_request={}, now=now
        )
        return _login_page(request, str(new_flow.id), csrf_token)
    # Re-render for an existing password-stage flow: rotate the CSRF token.
    csrf_token = await flow_service.rotate_csrf(db, existing)
    return _login_page(request, str(existing.id), csrf_token)


@router.post("/login")
async def login_submit(
    request: Request,
    db: DbDep,
    flow: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)

    flow_row = await flow_service.get_valid_flow(db, flow, source_ip=ip, now=now)
    if flow_row is None or request.cookies.get(FLOW_COOKIE) != flow:
        return error_page(request, "Your sign-in session expired. Please start over.", 400)
    if not flow_service.verify_flow_csrf(flow_row, csrf_token) or flow_row.stage != "password":
        return error_page(request, "Invalid request. Please start over.", 400)

    email = email.strip().lower()
    throttle = await ratelimit.check(db, source_ip=ip, account_key=email, now=now)
    if not throttle.allowed:
        await emit(
            db,
            AuthEventType.THROTTLE_APPLIED,
            source_ip=ip,
            success=False,
            detail={"retry_after": throttle.retry_after},
        )
        resp = error_page(request, "Too many attempts. Please wait and try again.", 429)
        resp.headers["Retry-After"] = str(throttle.retry_after)
        return resp

    user = await db.scalar(select(User).where(User.email == email))
    ok = False
    if user is None or user.status != "active":
        passwords.dummy_verify()  # keep timing flat for unknown/disabled accounts
    else:
        ok = passwords.verify_password(user.password_hash, password)

    if not ok:
        await ratelimit.register_failure(db, source_ip=ip, account_key=email, now=now)
        await emit(
            db,
            AuthEventType.LOGIN_PASSWORD_FAILURE,
            source_ip=ip,
            success=False,
            user_id=user.id if user else None,
        )
        return _login_page(
            request, flow, csrf_token, error="Incorrect email or password.", status=401
        )

    assert user is not None
    await ratelimit.reset_account(db, email)
    await emit(
        db, AuthEventType.LOGIN_PASSWORD_SUCCESS, source_ip=ip, success=True, user_id=user.id
    )

    second = flow_service.required_second_factor(user)
    flow_row.user_id = user.id
    flow_row.stage = second
    # Pin the now identity-bearing flow to the authenticating client's IP; the
    # second factor is enforced against this from here on.
    flow_row.source_ip = ip
    await db.flush()
    return RedirectResponse(f"/auth/{second}?flow={flow}", status_code=303)


async def get_stage_flow(
    request: Request, db: AsyncSession, flow_id: str | None, stage: str, *, for_update: bool = False
) -> LoginFlow | None:
    """Shared guard for second-factor pages: valid flow, right stage, cookie match."""
    now = datetime.now(UTC)
    flow_row = await flow_service.get_valid_flow(
        db, flow_id, source_ip=client_ip(request), now=now, for_update=for_update
    )
    if flow_row is None or flow_row.stage != stage or flow_row.user_id is None:
        return None
    if request.cookies.get(FLOW_COOKIE) != str(flow_row.id):
        return None
    return flow_row


async def redirect_if_authenticated(request: Request, db: AsyncSession) -> Response | None:
    """A double-submit of a second-factor form races the single-use flow: the
    first request burns it, the second finds it gone. If the browser already
    holds a live session, the first submit won, so send them to the signed-in
    page rather than a misleading 'start over' error."""
    session = await sessions.get_session_from_cookie(
        db,
        request.cookies.get(sessions.SESSION_COOKIE),
        source_ip=client_ip(request),
        now=datetime.now(UTC),
    )
    if session is None:
        return None
    return RedirectResponse("/auth/done", status_code=303)


async def flow_user(db: AsyncSession, flow_row: LoginFlow) -> User | None:
    assert flow_row.user_id is not None
    user = await db.get(User, flow_row.user_id)
    if user is None or user.status != "active":
        return None
    return user


def _continue_url(flow_row: LoginFlow) -> str | None:
    oidc_request = dict(flow_row.oidc_request)
    return f"/oidc/authorize?{urlencode(oidc_request)}" if oidc_request else None


def _login_response(
    request: Request, user: User, cookie_value: str, continue_url: str | None
) -> Response:
    """Land a completed login: resume the OIDC handshake if there is one, else
    show the signed-in page. Sets the session cookie and clears the flow cookie."""
    if continue_url:
        resp: Response = RedirectResponse(continue_url, status_code=303)
    else:
        resp = templates.TemplateResponse(request, "signedin.html", {"user": user})
    sessions.set_session_cookie(resp, cookie_value)
    resp.delete_cookie(FLOW_COOKIE, path="/")
    return resp


async def resume_completed_login(
    db: AsyncSession, flow_row: LoginFlow, request: Request
) -> tuple[str, str | None] | None:
    """Replay an already-completed flow (idempotent duplicate submit): re-mint a
    cookie for the session the winning submit created and return the same
    continuation. Returns None if that session is gone or no longer live."""
    assert flow_row.completed_session_id is not None
    session = await db.get(Session, flow_row.completed_session_id)
    if session is None or not await sessions.check_liveness(
        db, session, source_ip=client_ip(request), now=datetime.now(UTC)
    ):
        return None
    cookie_value = await sessions.reissue_cookie(db, session)
    return cookie_value, _continue_url(flow_row)


async def finalize_login(
    db: AsyncSession, flow_row: LoginFlow, user: User, amr: list[str], ip: str
) -> tuple[str, str | None]:
    """Create the session and mark the flow completed. The flow is retained (not
    deleted) and pinned to the new session so a duplicate submit replays the same
    outcome. Returns (cookie_value, continue_url or None)."""
    now = datetime.now(UTC)
    session, cookie_value = await sessions.create_session(
        db, user=user, source_ip=ip, amr=amr, now=now
    )
    flow_row.completed_session_id = session.id
    await db.flush()
    return cookie_value, _continue_url(flow_row)


async def complete_second_factor(
    request: Request, db: AsyncSession, flow_row: LoginFlow, user: User, amr: list[str]
) -> Response:
    """Second factor proven: create the IdP session and hand off."""
    cookie_value, continue_url = await finalize_login(db, flow_row, user, amr, client_ip(request))
    return _login_response(request, user, cookie_value, continue_url)


async def second_factor_throttle(request: Request, db: AsyncSession, user: User) -> Response | None:
    """Shared pre-check for TOTP/recovery submissions. Returns a 429 response or None."""
    now = datetime.now(UTC)
    ip = client_ip(request)
    decision = await ratelimit.check(db, source_ip=ip, account_key=user.email, now=now)
    if decision.allowed:
        return None
    await emit(
        db,
        AuthEventType.THROTTLE_APPLIED,
        source_ip=ip,
        success=False,
        user_id=user.id,
        detail={"retry_after": decision.retry_after},
    )
    resp = error_page(request, "Too many attempts. Please wait and try again.", 429)
    resp.headers["Retry-After"] = str(decision.retry_after)
    return resp


# --- TOTP verification -------------------------------------------------------


@router.get("/totp")
async def totp_form(request: Request, db: DbDep, flow: str | None = None) -> Response:
    flow_row = await get_stage_flow(request, db, flow, "totp")
    if flow_row is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    user = await flow_user(db, flow_row)
    if user is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    if await totp_service.get_totp_row(db, user, confirmed_only=True) is None:
        return RedirectResponse(f"/auth/enroll/totp?flow={flow_row.id}", status_code=303)
    csrf_token = await flow_service.rotate_csrf(db, flow_row)
    return templates.TemplateResponse(
        request,
        "totp.html",
        {"flow_id": str(flow_row.id), "csrf_token": csrf_token, "error": None},
    )


@router.post("/totp")
async def totp_submit(
    request: Request,
    db: DbDep,
    flow: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    code: Annotated[str, Form()],
) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    flow_row = await get_stage_flow(request, db, flow, "totp", for_update=True)
    if flow_row is None or not flow_service.verify_flow_csrf(flow_row, csrf_token):
        onward = await redirect_if_authenticated(request, db)
        return onward or error_page(request, "Invalid request. Please start over.")
    user = await flow_user(db, flow_row)
    if flow_row.completed_session_id is not None:
        # Duplicate submit of a single-use flow the first request already
        # completed: replay the same outcome instead of erroring.
        resumed = await resume_completed_login(db, flow_row, request)
        if resumed is None or user is None:
            return error_page(request, "Your sign-in session expired. Please start over.")
        return _login_response(request, user, *resumed)
    if user is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    throttled = await second_factor_throttle(request, db, user)
    if throttled is not None:
        return throttled
    row = await totp_service.get_totp_row(db, user, confirmed_only=True)
    if row is None:
        return RedirectResponse(f"/auth/enroll/totp?flow={flow_row.id}", status_code=303)

    secret = totp_service.decrypt_secret(get_secrets_backend(), row)
    if not totp_service.verify_code(secret, code.strip()):
        await ratelimit.register_failure(db, source_ip=ip, account_key=user.email, now=now)
        await emit(
            db, AuthEventType.LOGIN_TOTP_FAILURE, source_ip=ip, success=False, user_id=user.id
        )
        new_csrf = await flow_service.rotate_csrf(db, flow_row)
        return templates.TemplateResponse(
            request,
            "totp.html",
            {"flow_id": str(flow_row.id), "csrf_token": new_csrf, "error": "Incorrect code."},
            status_code=401,
        )

    await ratelimit.reset_account(db, user.email)
    await emit(db, AuthEventType.LOGIN_TOTP_SUCCESS, source_ip=ip, success=True, user_id=user.id)
    amr = ["pwd", "rc", "otp"] if flow_row.recovery_used else ["pwd", "otp"]
    return await complete_second_factor(request, db, flow_row, user, amr)


# --- TOTP enrollment ---------------------------------------------------------


@router.get("/enroll/totp")
async def enroll_totp_form(request: Request, db: DbDep, flow: str | None = None) -> Response:
    flow_row = await get_stage_flow(request, db, flow, "totp")
    if flow_row is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    user = await flow_user(db, flow_row)
    if user is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    if user.auth_tier == "admin":
        return error_page(request, "Admin accounts use passkeys, not TOTP.", 403)
    if await totp_service.get_totp_row(db, user, confirmed_only=True) is not None:
        return RedirectResponse(f"/auth/totp?flow={flow_row.id}", status_code=303)

    backend = get_secrets_backend()
    pending = await totp_service.get_totp_row(db, user, confirmed_only=False)
    if pending is None:
        secret = totp_service.generate_secret()
        await totp_service.store_pending_secret(db, backend, user.id, secret)
    else:
        secret = totp_service.decrypt_secret(backend, pending)

    csrf_token = await flow_service.rotate_csrf(db, flow_row)
    uri = totp_service.provisioning_uri(secret, user.email, issuer="hyproxy")
    return templates.TemplateResponse(
        request,
        "enroll_totp.html",
        {
            "flow_id": str(flow_row.id),
            "csrf_token": csrf_token,
            "secret": secret,
            "otpauth_uri": uri,
            "error": None,
        },
    )


@router.post("/enroll/totp")
async def enroll_totp_submit(
    request: Request,
    db: DbDep,
    flow: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    code: Annotated[str, Form()],
) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    flow_row = await get_stage_flow(request, db, flow, "totp")
    if flow_row is None or not flow_service.verify_flow_csrf(flow_row, csrf_token):
        onward = await redirect_if_authenticated(request, db)
        return onward or error_page(request, "Invalid request. Please start over.")
    user = await flow_user(db, flow_row)
    if user is None or user.auth_tier == "admin":
        return error_page(request, "Your sign-in session expired. Please start over.")
    throttled = await second_factor_throttle(request, db, user)
    if throttled is not None:
        return throttled
    pending = await totp_service.get_totp_row(db, user, confirmed_only=False)
    if pending is None or pending.confirmed_at is not None:
        return error_page(request, "No enrollment in progress. Please start over.")

    backend = get_secrets_backend()
    secret = totp_service.decrypt_secret(backend, pending)
    if not totp_service.verify_code(secret, code.strip()):
        await ratelimit.register_failure(db, source_ip=ip, account_key=user.email, now=now)
        uri = totp_service.provisioning_uri(secret, user.email, issuer="hyproxy")
        new_csrf = await flow_service.rotate_csrf(db, flow_row)
        return templates.TemplateResponse(
            request,
            "enroll_totp.html",
            {
                "flow_id": str(flow_row.id),
                "csrf_token": new_csrf,
                "secret": secret,
                "otpauth_uri": uri,
                "error": "Incorrect code. Scan the secret and try again.",
            },
            status_code=401,
        )

    pending.confirmed_at = now
    await db.flush()
    await ratelimit.reset_account(db, user.email)
    await emit(db, AuthEventType.ENROLL_TOTP, source_ip=ip, success=True, user_id=user.id)
    codes = await recovery_service.issue_batch(db, user.id)

    # Enrollment confirmation proves possession: complete the login now and show
    # the recovery codes exactly once on the way out.
    amr = ["pwd", "rc", "otp"] if flow_row.recovery_used else ["pwd", "otp"]
    oidc_request = dict(flow_row.oidc_request)
    session_resp: Response = templates.TemplateResponse(
        request,
        "recovery_codes.html",
        {
            "codes": codes,
            "continue_url": f"/oidc/authorize?{urlencode(oidc_request)}" if oidc_request else None,
        },
    )
    _session, cookie_value = await sessions.create_session(
        db, user=user, source_ip=ip, amr=amr, now=now
    )
    await flow_service.delete_flow(db, flow_row)
    sessions.set_session_cookie(session_resp, cookie_value)
    session_resp.delete_cookie(FLOW_COOKIE, path="/")
    return session_resp


# --- Recovery codes ----------------------------------------------------------


@router.get("/recovery")
async def recovery_form(request: Request, db: DbDep, flow: str | None = None) -> Response:
    flow_row = await get_stage_flow(request, db, flow, "totp")
    if flow_row is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    csrf_token = await flow_service.rotate_csrf(db, flow_row)
    return templates.TemplateResponse(
        request,
        "recovery.html",
        {"flow_id": str(flow_row.id), "csrf_token": csrf_token, "error": None},
    )


@router.post("/recovery")
async def recovery_submit(
    request: Request,
    db: DbDep,
    flow: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    code: Annotated[str, Form()],
) -> Response:
    now = datetime.now(UTC)
    ip = client_ip(request)
    flow_row = await get_stage_flow(request, db, flow, "totp")
    if flow_row is None or not flow_service.verify_flow_csrf(flow_row, csrf_token):
        onward = await redirect_if_authenticated(request, db)
        return onward or error_page(request, "Invalid request. Please start over.")
    user = await flow_user(db, flow_row)
    if user is None:
        return error_page(request, "Your sign-in session expired. Please start over.")
    throttled = await second_factor_throttle(request, db, user)
    if throttled is not None:
        return throttled

    if not await recovery_service.consume(db, user.id, code, now):
        await ratelimit.register_failure(db, source_ip=ip, account_key=user.email, now=now)
        await emit(
            db,
            AuthEventType.LOGIN_RECOVERY_CODE_FAILURE,
            source_ip=ip,
            success=False,
            user_id=user.id,
        )
        new_csrf = await flow_service.rotate_csrf(db, flow_row)
        return templates.TemplateResponse(
            request,
            "recovery.html",
            {
                "flow_id": str(flow_row.id),
                "csrf_token": new_csrf,
                "error": "That recovery code is not valid.",
            },
            status_code=401,
        )

    await ratelimit.reset_account(db, user.email)
    await emit(
        db, AuthEventType.LOGIN_RECOVERY_CODE_USED, source_ip=ip, success=True, user_id=user.id
    )
    # The authenticator is presumed lost: drop the old secret and force
    # re-enrollment before the login can complete.
    old = await totp_service.get_totp_row(db, user, confirmed_only=False)
    if old is not None:
        await db.delete(old)
    flow_row.recovery_used = True
    await db.flush()
    return RedirectResponse(f"/auth/enroll/totp?flow={flow_row.id}", status_code=303)

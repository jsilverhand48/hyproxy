"""The password gate for public resources (browser-facing, no IdP involved).

A resource with `public_access` set is reachable by anyone on the internet who
can supply one shared password. There is no user account, no IdP session, no
role, and no Policy evaluation behind it -- which is exactly why the surface is
kept as small as it is:

  * The gate is served on the RESOURCE's own hostname, under /__hyproxy/, so the
    flow never leaves the origin. That lets the access cookie carry the __Host-
    prefix (Secure, Path=/, and no Domain attribute), which pins it to the one
    hostname that issued it. It is never sent to a sibling subdomain the way the
    cross-subdomain gateway cookie is.
  * Only the paths listed in `public_paths` exist. Everything else on the host
    404s from authz/check.py, so a public resource never becomes a way to
    enumerate the backend.
  * Attempts run through the same DB-backed throttle as IdP logins
    (security/ratelimit.py), keyed per source IP and per resource, which also
    bounds argon2 CPU on an internet-facing endpoint.
  * A granted session is bound to its resource id and re-checked on every
    request, so a cookie minted for one public resource cannot be replayed at
    another.

Host resolution: the data plane proxies this path with `Out.Host` rewritten to
the backend's own vhost (see newReverseProxy in dataplane/internal/proxy), so
the original hostname arrives as X-Forwarded-Host. That header is trustworthy
here and only here: ReverseProxy.SetXForwarded() drops any client-supplied
value, and the data plane only reaches this handler for a host it already
matched in its own route table. A request without it is not from the data plane
and gets a 404.
"""

import logging
import secrets as pysecrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import CursorResult, delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core.crypto import constant_time_equals, new_token, sha256_hex
from hyproxy.core.netutil import resolve_client_ip
from hyproxy.db.engine import get_db
from hyproxy.db.models import AuditLog, PublicSession, Resource
from hyproxy.policy import pathglob
from hyproxy.security import ratelimit
from hyproxy.security.passwords import dummy_verify, hash_password, verify_password

# Reserved path space on a public resource's hostname. The data plane routes
# anything under this prefix to the gate instead of the backend, so it must stay
# in sync with publicGatePrefix in dataplane/internal/proxy/server.go.
PUBLIC_GATE_PREFIX = "/__hyproxy/"
PUBLIC_GATE_PATH = "/__hyproxy/gate"

router = APIRouter()

logger = logging.getLogger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]

# Self-contained: /static is served by the IdP app on the issuer host and is not
# reachable on a resource hostname, so this template inlines its own styling and
# ships no script.
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# Unambiguous alphabet (no 0/O, 1/l/I) so a generated password survives being
# read aloud or copied by hand. 4 groups of 5 over 32 symbols is ~100 bits.
_PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # noqa: S105 (alphabet)
_PASSWORD_GROUPS = 4
_PASSWORD_GROUP_LEN = 5


def generate_password() -> str:
    """A fresh share password. Returned to the admin once and never stored."""
    groups = [
        "".join(pysecrets.choice(_PASSWORD_ALPHABET) for _ in range(_PASSWORD_GROUP_LEN))
        for _ in range(_PASSWORD_GROUPS)
    ]
    return "-".join(groups)


def set_public_password(resource: Resource, now: datetime) -> str:
    """Generate, hash onto the resource, and return the cleartext once."""
    password = generate_password()
    resource.public_password_hash = hash_password(password)
    resource.public_password_set_at = now
    return password


async def revoke_public_sessions(db: AsyncSession, resource_id: uuid.UUID) -> int:
    """Kill every live session on a public resource.

    Called whenever what the link grants changes: password rotation, public mode
    being turned off, or the exposed path list being edited. Returns the number
    of sessions revoked.
    """
    result = cast(
        CursorResult[Any],
        await db.execute(
            update(PublicSession)
            .where(PublicSession.resource_id == resource_id, PublicSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        ),
    )
    return int(result.rowcount or 0)


def set_public_cookie(response: Response, value: str, *, max_age: int) -> None:
    """Set the access cookie.

    Deliberately unlike set_gateway_cookie: no `domain`, because the __Host-
    prefix forbids one and host-only scoping is the point. samesite="lax" rather
    than "strict" so that following the shared link from a chat client or an
    email still carries an existing session on the top-level navigation.
    """
    response.set_cookie(
        get_settings().public_cookie_name,
        value,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=max_age,
    )


def _csrf_cookie_name() -> str:
    return f"{get_settings().public_cookie_name}_csrf"


async def resolve_public_session(
    db: AsyncSession,
    cookie_value: str | None,
    *,
    resource_id: uuid.UUID,
    source_ip: str,
    now: datetime,
) -> PublicSession | None:
    """Access cookie -> live public session for THIS resource, or None.

    The resource_id check is what keeps public resources isolated from one
    another: the cookie is host-scoped by the browser, but a server-side check
    is what actually enforces it.
    """
    if not cookie_value or "." not in cookie_value:
        return None
    sid_str, _, secret = cookie_value.partition(".")
    try:
        sid = uuid.UUID(sid_str)
    except ValueError:
        return None
    row = await db.get(PublicSession, sid)
    if row is None or row.revoked_at is not None:
        return None
    if row.resource_id != resource_id:
        return None
    if not constant_time_equals(sha256_hex(secret), row.cookie_secret_hash):
        return None
    if row.expires_at <= now:
        return None
    if get_settings().public_session_bind_ip and str(row.source_ip) != source_ip:
        return None
    row.last_seen_at = now
    return row


async def _resource_for_request(db: AsyncSession, request: Request) -> Resource | None:
    """The public resource this gate request belongs to, by forwarded host."""
    forwarded = request.headers.get("x-forwarded-host", "")
    host = forwarded.split(",")[0].strip().lower().rstrip(".")
    if not host:
        return None
    # Strip any port the data plane forwarded; public_host never carries one.
    if host.startswith("["):  # bracketed IPv6 literal
        host = host.partition("]")[0].lstrip("[")
    elif host.count(":") == 1:
        host = host.partition(":")[0]
    if not host:
        return None
    resource: Resource | None = await db.scalar(
        select(Resource).where(
            Resource.public_host == host,
            Resource.enabled.is_(True),
            Resource.public_access.is_(True),
        )
    )
    return resource


def _safe_rd(rd: str, resource: Resource) -> str:
    """Sanitize the post-login return path.

    Must be a same-origin absolute path AND already exposed by the resource, so
    the gate is neither an open redirect nor a way to probe non-public paths.
    Anything else falls back to the first pattern's fixed prefix.
    """
    fallback = pathglob.literal_prefix((resource.public_paths or ["/"])[0])
    if not rd or not rd.startswith("/") or rd.startswith("//") or "\\" in rd:
        return fallback
    path = rd.split("?", 1)[0].split("#", 1)[0]
    if not pathglob.matches(resource.public_paths, path):
        return fallback
    return rd


def _harden(response: Response) -> Response:
    """Gate responses are never cacheable and never indexable."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    return response


async def _audit(
    db: AsyncSession,
    *,
    resource_id: uuid.UUID | None,
    decision: str,
    reason: str,
    source_ip: str,
) -> None:
    db.add(
        AuditLog(
            user_id=None,
            resource_id=resource_id,
            port=None,
            decision=decision,
            reason=reason,
            source_ip=source_ip,
        )
    )
    await db.flush()


def _render(
    request: Request,
    resource: Resource,
    rd: str,
    csrf: str,
    *,
    error: str = "",
    status_code: int = 200,
    retry_after: int = 0,
) -> Response:
    response = templates.TemplateResponse(
        request,
        "gate.html",
        {
            "resource_name": resource.name,
            "rd": rd,
            "csrf": csrf,
            "error": error,
            "action": PUBLIC_GATE_PATH,
        },
        status_code=status_code,
    )
    response.set_cookie(
        _csrf_cookie_name(),
        csrf,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=get_settings().public_gate_csrf_ttl,
    )
    if retry_after:
        response.headers["Retry-After"] = str(retry_after)
    return _harden(response)


@router.get(PUBLIC_GATE_PATH, response_class=HTMLResponse)
async def gate_form(request: Request, db: DbDep, rd: str = "") -> Response:
    resource = await _resource_for_request(db, request)
    if resource is None:
        return _harden(Response(status_code=404))
    return _render(request, resource, _safe_rd(rd, resource), new_token(16))


@router.post(PUBLIC_GATE_PATH, response_class=HTMLResponse)
async def gate_submit(
    request: Request,
    db: DbDep,
    password: Annotated[str, Form()] = "",
    rd: Annotated[str, Form()] = "",
    csrf: Annotated[str, Form()] = "",
) -> Response:
    settings = get_settings()
    now = datetime.now(UTC)
    resource = await _resource_for_request(db, request)
    if resource is None:
        return _harden(Response(status_code=404))

    source_ip = resolve_client_ip(request)
    target = _safe_rd(rd, resource)

    # Same-origin form, so a matching one-shot cookie is sufficient CSRF cover.
    cookie_csrf = request.cookies.get(_csrf_cookie_name(), "")
    if not csrf or not cookie_csrf or not constant_time_equals(csrf, cookie_csrf):
        return _render(
            request,
            resource,
            target,
            new_token(16),
            error="That form expired. Try again.",
            status_code=400,
        )

    throttle = await ratelimit.check(
        db, source_ip=source_ip, account_key=f"public:{resource.id}", now=now
    )
    if not throttle.allowed:
        await _audit(
            db,
            resource_id=resource.id,
            decision="deny",
            reason="public_throttled",
            source_ip=source_ip,
        )
        return _render(
            request,
            resource,
            target,
            new_token(16),
            error="Too many attempts. Wait a moment and try again.",
            status_code=429,
            retry_after=throttle.retry_after,
        )

    stored = resource.public_password_hash
    if stored is None:
        # No password generated yet: burn the same argon2 time as a real miss so
        # an unconfigured resource is indistinguishable from a wrong password.
        dummy_verify()
        ok = False
    else:
        ok = verify_password(stored, password)

    if not ok:
        await ratelimit.register_failure(
            db, source_ip=source_ip, account_key=f"public:{resource.id}", now=now
        )
        await _audit(
            db,
            resource_id=resource.id,
            decision="deny",
            reason="public_bad_password",
            source_ip=source_ip,
        )
        logger.info(
            "public gate failure", extra={"resource": resource.name, "source_ip": source_ip}
        )
        return _render(
            request,
            resource,
            target,
            new_token(16),
            error="Incorrect password.",
            status_code=401,
        )

    secret = new_token(32)
    session = PublicSession(
        resource_id=resource.id,
        cookie_secret_hash=sha256_hex(secret),
        source_ip=source_ip if settings.public_session_bind_ip else None,
        expires_at=now + timedelta(seconds=settings.public_session_ttl),
        last_seen_at=now,
    )
    db.add(session)
    await db.flush()
    await _audit(
        db,
        resource_id=resource.id,
        decision="allow",
        reason="public_password_accepted",
        source_ip=source_ip,
    )
    response = RedirectResponse(target, status_code=303)
    set_public_cookie(response, f"{session.id}.{secret}", max_age=settings.public_session_ttl)
    response.delete_cookie(_csrf_cookie_name(), path="/")
    return _harden(response)


async def gc_public_sessions(db: AsyncSession, now: datetime) -> int:
    """Drop sessions that expired or were revoked. Mirrors gc_login_states."""
    result = cast(
        CursorResult[Any],
        await db.execute(
            delete(PublicSession).where(
                or_(PublicSession.expires_at <= now, PublicSession.revoked_at.is_not(None))
            )
        ),
    )
    return int(result.rowcount or 0)

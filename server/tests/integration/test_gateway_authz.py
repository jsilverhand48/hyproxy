"""Gateway RP + ext-authz decision point: the browser journey through
/gateway/start -> IdP login -> /gateway/callback, then per-request
/authz/check decisions with policy evaluation and audit rows."""

import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

import httpx
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import create_user, enroll_confirmed_totp, extract_form_fields
from hyproxy.authz.app import create_app as create_authz_app
from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.engine import get_db
from hyproxy.db.models import (
    AuditLog,
    GatewayLoginState,
    GatewaySession,
    OAuthClient,
    Policy,
    Resource,
    Role,
    Session,
    User,
    UserRole,
)

pytestmark = pytest.mark.integration

PW = "pw-gateway-tests"
APP_HOST = "app.local.test"
HashFn = Callable[[str], str]


@pytest.fixture
async def authz_client(
    db: AsyncSession, idp_client: httpx.AsyncClient, secrets_backend: FileSecretsBackend
) -> AsyncIterator[httpx.AsyncClient]:
    await key_service.bootstrap_if_empty(db, secrets_backend, datetime.now(UTC))
    settings = get_settings()
    db.add(
        OAuthClient(
            client_id=settings.gateway_client_id,
            client_name="Gateway",
            redirect_uris=[f"{settings.external_scheme}://{settings.auth_host}/gateway/callback"],
        )
    )
    await db.flush()

    app = create_authz_app()
    app.state.idp_http = idp_client  # backchannel token exchange, ASGI-wired

    async def override_db() -> AsyncIterator[AsyncSession]:
        yield db

    app.dependency_overrides[get_db] = override_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url=f"https://{get_settings().auth_host}"
    ) as client:
        yield client


async def make_resource(db: AsyncSession, *, public_host: str = APP_HOST) -> Resource:
    resource = Resource(
        name=f"res-{uuid.uuid4()}",
        protocol="http",
        public_host=public_host,
        host="10.0.0.10",
        ports=[8080],
    )
    db.add(resource)
    await db.flush()
    return resource


async def grant(
    db: AsyncSession,
    user: User,
    resource: Resource,
    *,
    action: str = "allow",
    allowed_paths: list[str] | None = None,
    allowed_ports: list[int] | None = None,
) -> Role:
    role = Role(name=f"role-{uuid.uuid4()}")
    db.add(role)
    await db.flush()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    db.add(
        Policy(
            role_id=role.id,
            resource_id=resource.id,
            action=action,
            allowed_paths=allowed_paths,
            allowed_ports=allowed_ports,
            conditions_json={},
        )
    )
    await db.flush()
    return role


async def check(
    authz: httpx.AsyncClient,
    *,
    host: str = APP_HOST,
    uri: str = "/",
    cookie: str | None = None,
    source_ip: str = "127.0.0.1",
    backend_port: int | None = 8080,
) -> httpx.Response:
    return await authz.post(
        "/authz/check",
        json={
            "host": host,
            "method": "GET",
            "uri": uri,
            "source_ip": source_ip,
            "backend_port": backend_port,
            "gateway_cookie": cookie,
        },
    )


async def gateway_login(
    authz: httpx.AsyncClient,
    idp: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> tuple[User, str]:
    """Full browser journey; returns (user, gateway_cookie_value)."""
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)

    rd = f"https://{APP_HOST}/photos"
    start = await authz.get("/gateway/start", params={"rd": rd})
    assert start.status_code == 303, start.text
    authorize_url = start.headers["location"]
    assert authorize_url.startswith(get_settings().issuer.rstrip("/"))

    # Browser follows to the IdP (ASGI client: use path + query).
    parts = urlsplit(authorize_url)
    resp = await idp.get(f"{parts.path}?{parts.query}")
    assert resp.status_code == 303 and resp.headers["location"].startswith("/auth/login")

    # Password + TOTP.
    page = await idp.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    resp = await idp.post("/auth/login", data={**fields, "email": user.email, "password": PW})
    page = await idp.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    resp = await idp.post("/auth/totp", data={**fields, "code": pyotp.TOTP(secret).now()})
    assert resp.status_code == 303
    resp = await idp.get(resp.headers["location"])  # authorize resumes
    assert resp.status_code == 302
    callback_url = resp.headers["location"]
    assert callback_url.startswith(f"https://{get_settings().auth_host}/gateway/callback")

    cb = urlsplit(callback_url)
    resp = await authz.get(f"{cb.path}?{cb.query}")
    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == rd

    cookie = authz.cookies.get(get_settings().gateway_cookie_name)
    assert cookie
    return user, cookie


async def test_full_gateway_login_and_allow(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    resource = await make_resource(db)
    user, cookie = await gateway_login(
        authz_client, idp_client, db, make_password_hash, secrets_backend
    )
    await grant(db, user, resource)

    resp = await check(authz_client, cookie=cookie, uri="/photos?album=1")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["headers"]["X-Forwarded-User"] == user.email
    assert body["headers"]["X-Auth-User-Id"] == user.external_id
    assert body["headers"]["X-Auth-Roles"]

    audits = (await db.scalars(select(AuditLog).where(AuditLog.resource_id == resource.id))).all()
    assert any(a.decision == "allow" and a.user_id == user.id for a in audits)


async def test_unauthenticated_check_returns_login_redirect(
    authz_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    await make_resource(db)
    resp = await check(authz_client, uri="/photos?x=1")
    body = resp.json()
    assert body["decision"] == "auth_required"
    expected_rd = quote(f"https://{APP_HOST}/photos?x=1", safe="")
    assert body["redirect"] == (
        f"https://{get_settings().auth_host}/gateway/start?rd={expected_rd}"
    )


async def test_default_deny_without_policy(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    await make_resource(db)
    _user, cookie = await gateway_login(
        authz_client, idp_client, db, make_password_hash, secrets_backend
    )
    resp = await check(authz_client, cookie=cookie)
    body = resp.json()
    assert body["decision"] == "deny" and body["reason"] == "default_deny"


async def test_path_scoping_and_explicit_deny(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    resource = await make_resource(db)
    user, cookie = await gateway_login(
        authz_client, idp_client, db, make_password_hash, secrets_backend
    )
    await grant(db, user, resource, allowed_paths=["/photos"])
    assert (await check(authz_client, cookie=cookie, uri="/photos/1")).json()["decision"] == "allow"
    assert (await check(authz_client, cookie=cookie, uri="/admin")).json()["decision"] == "deny"

    await grant(db, user, resource, action="deny", allowed_paths=["/photos/private"])
    assert (await check(authz_client, cookie=cookie, uri="/photos/1")).json()["decision"] == "allow"
    denied = await check(authz_client, cookie=cookie, uri="/photos/private/x")
    assert denied.json()["decision"] == "deny" and denied.json()["reason"] == "explicit_deny"


async def test_unknown_host_denied(authz_client: httpx.AsyncClient, db: AsyncSession) -> None:
    resp = await check(authz_client, host="ghost.local.test")
    assert resp.json() == {
        "decision": "deny",
        "reason": "unknown_resource",
        "headers": {},
        "redirect": "",
    }


async def test_idp_revocation_kills_gateway_access(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    resource = await make_resource(db)
    user, cookie = await gateway_login(
        authz_client, idp_client, db, make_password_hash, secrets_backend
    )
    await grant(db, user, resource)
    assert (await check(authz_client, cookie=cookie)).json()["decision"] == "allow"

    gw = await db.scalar(select(GatewaySession).where(GatewaySession.user_id == user.id))
    assert gw is not None
    idp_session = await db.get(Session, gw.idp_session_id)
    assert idp_session is not None
    idp_session.revoked_at = datetime.now(UTC)
    await db.flush()

    assert (await check(authz_client, cookie=cookie)).json()["decision"] == "auth_required"


async def test_ip_change_forces_reauth(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    resource = await make_resource(db)
    user, cookie = await gateway_login(
        authz_client, idp_client, db, make_password_hash, secrets_backend
    )
    await grant(db, user, resource)
    # A gateway cookie replayed from a different source IP than the session's
    # origin is refused: the gateway session is IP-bound to the data plane's
    # consistent view of the client.
    roamed = await check(authz_client, cookie=cookie, source_ip="198.51.100.7")
    assert roamed.json()["decision"] == "auth_required"
    # But a single mismatched request does not brick the session: the original
    # IP still works. IP binding lives on the gateway session's own origin, not
    # on the IdP session's separate browser->IdP vantage (re-checking that from
    # the data plane was forcing a spurious cross-plane re-auth loop).
    assert (await check(authz_client, cookie=cookie)).json()["decision"] == "allow"


async def test_cross_plane_ip_mismatch_does_not_loop(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    """Regression: the IdP session is bound to the browser->IdP hop, while the
    gateway check runs at the data plane's separate vantage. When those two
    vantage points resolve the client to different IPs (a common deployment),
    per-request checks must still allow as long as the gateway session's own
    origin matches - otherwise every resource request bounces back to login and
    the user never leaves the 2FA/redirect chain."""
    resource = await make_resource(db)
    user, cookie = await gateway_login(
        authz_client, idp_client, db, make_password_hash, secrets_backend
    )
    await grant(db, user, resource)

    gw = await db.scalar(select(GatewaySession).where(GatewaySession.user_id == user.id))
    assert gw is not None
    idp_session = await db.get(Session, gw.idp_session_id)
    assert idp_session is not None
    # The IdP recorded a different client IP than the data plane reports on
    # /authz/check (distinct ingress paths). This must not deny access.
    idp_session.source_ip = "203.0.113.50"
    await db.flush()

    allowed = await check(authz_client, cookie=cookie, source_ip="127.0.0.1")
    assert allowed.json()["decision"] == "allow", allowed.text


async def test_start_rejects_unregistered_return_url(
    authz_client: httpx.AsyncClient, db: AsyncSession
) -> None:
    await make_resource(db)
    for rd in (
        "https://evil.example/",
        "http://" + APP_HOST + "/downgrade",
        "javascript:alert(1)",
        "",
    ):
        resp = await authz_client.get("/gateway/start", params={"rd": rd})
        assert resp.status_code == 400, rd


async def test_callback_state_single_use(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    resource = await make_resource(db)
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)
    _ = resource

    start = await authz_client.get("/gateway/start", params={"rd": f"https://{APP_HOST}/x"})
    parts = urlsplit(start.headers["location"])
    resp = await idp_client.get(f"{parts.path}?{parts.query}")
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    resp = await idp_client.post(
        "/auth/login", data={**fields, "email": user.email, "password": PW}
    )
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    resp = await idp_client.post("/auth/totp", data={**fields, "code": pyotp.TOTP(secret).now()})
    resp = await idp_client.get(resp.headers["location"])
    cb = urlsplit(resp.headers["location"])

    first = await authz_client.get(f"{cb.path}?{cb.query}")
    assert first.status_code == 303
    replay = await authz_client.get(f"{cb.path}?{cb.query}")
    assert replay.status_code == 400
    # State rows are single-use and the replay consumed nothing.
    states = (await db.scalars(select(GatewayLoginState))).all()
    assert states == []


async def test_gateway_logout_revokes(
    authz_client: httpx.AsyncClient,
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    resource = await make_resource(db)
    user, cookie = await gateway_login(
        authz_client, idp_client, db, make_password_hash, secrets_backend
    )
    await grant(db, user, resource)
    assert (await check(authz_client, cookie=cookie)).json()["decision"] == "allow"
    out = await authz_client.get("/gateway/logout")
    assert out.status_code == 200
    assert (await check(authz_client, cookie=cookie)).json()["decision"] == "auth_required"

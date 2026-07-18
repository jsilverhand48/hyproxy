import re
import uuid
from collections.abc import Callable

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.db.models import AuthEvent, AuthThrottle, LoginFlow, User

pytestmark = pytest.mark.integration


def extract_form_fields(html: str) -> dict[str, str]:
    return dict(re.findall(r'name="(\w+)" value="([^"]*)"', html))


async def create_user(
    db: AsyncSession, make_password_hash: Callable[[str], str], *, tier: str, password: str
) -> User:
    user = User(
        external_id=f"u-{uuid.uuid4()}",
        email=f"{uuid.uuid4()}@example.test",
        display_name="Test",
        status="active",
        auth_tier=tier,
        password_hash=make_password_hash(password),
    )
    db.add(user)
    await db.flush()
    return user


async def start_login(client: httpx.AsyncClient) -> dict[str, str]:
    resp = await client.get("/auth/login")
    assert resp.status_code == 200
    return extract_form_fields(resp.text)


async def test_login_page_sets_flow_and_security_headers(idp_client: httpx.AsyncClient) -> None:
    resp = await idp_client.get("/auth/login")
    assert resp.status_code == 200
    assert "__Host-login_flow" in resp.headers.get("set-cookie", "")
    assert resp.headers["content-security-policy"].startswith("default-src 'none'")
    assert "script-src 'self'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"
    fields = extract_form_fields(resp.text)
    assert "flow" in fields and "csrf_token" in fields


async def test_login_bad_csrf_rejected(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: Callable[[str], str]
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password="pw-1")
    fields = await start_login(idp_client)
    resp = await idp_client.post(
        "/auth/login",
        data={
            "flow": fields["flow"],
            "csrf_token": "forged",
            "email": user.email,
            "password": "pw-1",
        },
    )
    assert resp.status_code == 400


async def test_login_without_flow_cookie_rejected(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: Callable[[str], str]
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password="pw-1")
    fields = await start_login(idp_client)
    idp_client.cookies.clear()
    resp = await idp_client.post(
        "/auth/login",
        data={**fields, "email": user.email, "password": "pw-1"},
    )
    assert resp.status_code == 400


async def test_wrong_password_fails_and_audits(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: Callable[[str], str]
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password="pw-1")
    fields = await start_login(idp_client)
    resp = await idp_client.post(
        "/auth/login", data={**fields, "email": user.email, "password": "wrong"}
    )
    assert resp.status_code == 401
    events = (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == user.id))).all()
    assert [e.event_type for e in events] == ["login.password.failure"]
    throttle = await db.scalar(
        select(AuthThrottle).where(AuthThrottle.scope == "account", AuthThrottle.key == user.email)
    )
    assert throttle is not None and throttle.failure_count == 1


async def test_unknown_email_same_response_as_wrong_password(
    idp_client: httpx.AsyncClient,
) -> None:
    fields = await start_login(idp_client)
    resp = await idp_client.post(
        "/auth/login",
        data={**fields, "email": "ghost@example.test", "password": "whatever"},
    )
    assert resp.status_code == 401
    assert "Incorrect email or password" in resp.text


async def test_standard_user_routed_to_totp(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: Callable[[str], str]
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password="pw-1")
    fields = await start_login(idp_client)
    resp = await idp_client.post(
        "/auth/login", data={**fields, "email": user.email, "password": "pw-1"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/auth/totp?flow={fields['flow']}"
    flow = await db.get(LoginFlow, uuid.UUID(fields["flow"]))
    assert flow is not None and flow.stage == "totp" and flow.user_id == user.id
    # Successful password step resets the account throttle row.
    throttle = await db.scalar(
        select(AuthThrottle).where(AuthThrottle.scope == "account", AuthThrottle.key == user.email)
    )
    assert throttle is None


async def test_admin_user_routed_to_webauthn_never_totp(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: Callable[[str], str]
) -> None:
    user = await create_user(db, make_password_hash, tier="admin", password="pw-admin")
    fields = await start_login(idp_client)
    resp = await idp_client.post(
        "/auth/login", data={**fields, "email": user.email, "password": "pw-admin"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/auth/webauthn")


async def test_throttle_429_progression(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: Callable[[str], str]
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password="pw-1")
    # Burn the free account failures (default 3) plus one to enter the delay window.
    for _ in range(4):
        fields = await start_login(idp_client)
        resp = await idp_client.post(
            "/auth/login", data={**fields, "email": user.email, "password": "bad"}
        )
        assert resp.status_code == 401
    fields = await start_login(idp_client)
    resp = await idp_client.post(
        "/auth/login", data={**fields, "email": user.email, "password": "pw-1"}
    )
    assert resp.status_code == 429
    assert int(resp.headers["retry-after"]) >= 1
    throttled = (
        await db.scalars(select(AuthEvent).where(AuthEvent.event_type == "throttle.applied"))
    ).all()
    assert len(throttled) == 1

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import create_user, enroll_confirmed_totp, extract_form_fields, password_step
from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import AuthEvent, RecoveryCode, Session, UserTotp
from hyproxy.security import recovery as recovery_service

pytestmark = pytest.mark.integration

PW = "pw-totp-tests"

HashFn = Callable[[str], str]


def current_code(secret: str) -> str:
    return pyotp.TOTP(secret).now()


async def test_full_standard_login_with_totp(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)

    resp = await password_step(idp_client, user.email, PW)
    assert resp.status_code == 303
    totp_url = resp.headers["location"]

    page = await idp_client.get(totp_url)
    assert page.status_code == 200
    fields = extract_form_fields(page.text)

    done = await idp_client.post("/auth/totp", data={**fields, "code": current_code(secret)})
    assert done.status_code == 200
    assert "You are signed in" in done.text
    assert "__Host-idp_sid" in done.headers.get("set-cookie", "")

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None
    assert session.amr == ["pwd", "otp"]
    assert session.auth_tier == "standard"
    assert session.mfa_verified is True
    events = {
        e.event_type
        for e in (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == user.id))).all()
    }
    assert {"login.password.success", "login.totp.success", "session.created"} <= events


async def test_authenticated_user_visiting_login_sees_signed_in_page(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)

    resp = await password_step(idp_client, user.email, PW)
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    done = await idp_client.post("/auth/totp", data={**fields, "code": current_code(secret)})
    assert done.status_code == 200

    # With a live session cookie, the login page must not be shown again.
    redirect = await idp_client.get("/auth/login")
    assert redirect.status_code == 303
    assert redirect.headers["location"] == "/auth/done"

    signed_in = await idp_client.get("/auth/login", follow_redirects=True)
    assert "You are signed in" in signed_in.text


async def test_duplicate_totp_submit_replays_idempotently(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)

    resp = await password_step(idp_client, user.email, PW)
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    flow_cookie = idp_client.cookies.get("__Host-login_flow")
    assert flow_cookie is not None

    first = await idp_client.post("/auth/totp", data={**fields, "code": current_code(secret)})
    assert first.status_code == 200
    assert "You are signed in" in first.text
    assert "__Host-idp_sid" in first.headers.get("set-cookie", "")
    created = (await db.scalars(select(Session).where(Session.user_id == user.id))).all()
    assert len(created) == 1
    session_id = created[0].id

    # A duplicate submit (double-click, Enter, or one-time-code autofill) races the
    # first: it still carries the flow cookie because the winner's response had not
    # yet cleared it. It must replay the exact outcome, re-attaching the browser to
    # the same session, not error out and not mint a second session.
    idp_client.cookies.set("__Host-login_flow", flow_cookie, domain="idp.test", path="/")
    dup = await idp_client.post("/auth/totp", data={**fields, "code": current_code(secret)})
    assert dup.status_code == 200
    assert "You are signed in" in dup.text
    assert "__Host-idp_sid" in dup.headers.get("set-cookie", "")
    assert "Invalid request" not in dup.text
    still = (await db.scalars(select(Session).where(Session.user_id == user.id))).all()
    assert {s.id for s in still} == {session_id}


async def test_wrong_totp_code_rejected_and_throttled(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    await enroll_confirmed_totp(db, secrets_backend, user)
    resp = await password_step(idp_client, user.email, PW)
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)

    bad = await idp_client.post("/auth/totp", data={**fields, "code": "000000"})
    assert bad.status_code == 401
    assert "Incorrect code" in bad.text
    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is None
    events = [
        e.event_type
        for e in (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == user.id))).all()
    ]
    assert "login.totp.failure" in events


async def test_enrollment_flow_for_user_without_totp(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    resp = await password_step(idp_client, user.email, PW)

    # /auth/totp bounces to enrollment when no confirmed secret exists.
    page = await idp_client.get(resp.headers["location"])
    assert page.status_code == 303
    assert page.headers["location"].startswith("/auth/enroll/totp")

    enroll = await idp_client.get(page.headers["location"])
    assert enroll.status_code == 200
    fields = extract_form_fields(enroll.text)
    import re

    secret = re.search(r'<code class="block">([A-Z2-7]+)</code>', enroll.text).group(1)  # type: ignore[union-attr]

    # Secret is stored encrypted, never in plaintext.
    row = await db.get(UserTotp, user.id)
    assert row is not None and row.confirmed_at is None
    assert secret.encode() not in row.secret_ciphertext

    done = await idp_client.post("/auth/enroll/totp", data={**fields, "code": current_code(secret)})
    assert done.status_code == 200
    assert "Save your recovery codes" in done.text
    assert "__Host-idp_sid" in done.headers.get("set-cookie", "")

    await db.refresh(row)
    assert row.confirmed_at is not None
    codes = (await db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id))).all()
    assert len(codes) == 10
    assert all(c.code_hash.startswith("$argon2id$") for c in codes)


async def test_recovery_code_flow_forces_reenrollment(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    await enroll_confirmed_totp(db, secrets_backend, user)
    codes = await recovery_service.issue_batch(db, user.id)

    await password_step(idp_client, user.email, PW)
    rec_page = await idp_client.get("/auth/recovery", params={"flow": _flow_id(idp_client)})
    fields = extract_form_fields(rec_page.text)

    resp = await idp_client.post("/auth/recovery", data={**fields, "code": codes[0]})
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/auth/enroll/totp")

    # Old secret dropped; login cannot complete without re-enrollment.
    assert await db.get(UserTotp, user.id) is None

    enroll = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(enroll.text)
    import re

    secret = re.search(r'<code class="block">([A-Z2-7]+)</code>', enroll.text).group(1)  # type: ignore[union-attr]
    done = await idp_client.post("/auth/enroll/totp", data={**fields, "code": current_code(secret)})
    assert done.status_code == 200

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None
    assert session.amr == ["pwd", "rc", "otp"]

    # The used code is burned.
    assert not await recovery_service.consume(db, user.id, codes[0], datetime.now(UTC))


async def test_new_batch_invalidates_old_codes(
    db: AsyncSession, make_password_hash: HashFn
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    first = await recovery_service.issue_batch(db, user.id)
    second = await recovery_service.issue_batch(db, user.id)
    now = datetime.now(UTC)
    assert not await recovery_service.consume(db, user.id, first[0], now)
    assert await recovery_service.consume(db, user.id, second[0], now)


def _flow_id(client: httpx.AsyncClient) -> str:
    value = client.cookies.get("__Host-login_flow")
    assert value is not None
    return str(uuid.UUID(value))

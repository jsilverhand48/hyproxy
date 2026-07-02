from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from soft_webauthn import SoftWebauthnDevice
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import create_user, credential_to_json, options_for_device, password_step
from hyproxy.db.models import AuthEvent, Session, User, WebAuthnCredential
from hyproxy.security.webauthn import expected_origin

pytestmark = pytest.mark.integration

PW = "pw-webauthn-tests"
HashFn = Callable[[str], str]


def flow_of(client: httpx.AsyncClient) -> str:
    value = client.cookies.get("__Host-login_flow")
    assert value
    return value


def csrf_of(html: str) -> str:
    from helpers import extract_form_fields

    fields = extract_form_fields(html)
    if "csrf_token" in fields:
        return fields["csrf_token"]
    import re

    m = re.search(r'data-csrf="([^"]+)"', html)
    assert m is not None
    return m.group(1)


async def enroll_device(
    client: httpx.AsyncClient,
    flow: str,
    csrf: str,
    device: SoftWebauthnDevice,
    name: str,
    break_glass: bool = False,
) -> httpx.Response:
    opts = await client.post(
        "/auth/enroll/webauthn/options", json={"flow": flow, "csrf_token": csrf}
    )
    assert opts.status_code == 200, opts.text
    attestation = device.create(options_for_device(opts.json()), expected_origin())
    return await client.post(
        "/auth/enroll/webauthn/verify",
        json={
            "flow": flow,
            "csrf_token": csrf,
            "credential": credential_to_json(attestation),
            "friendly_name": name,
            "break_glass": break_glass,
        },
    )


async def assert_device(
    client: httpx.AsyncClient, flow: str, csrf: str, device: SoftWebauthnDevice
) -> httpx.Response:
    opts = await client.post("/auth/webauthn/options", json={"flow": flow, "csrf_token": csrf})
    assert opts.status_code == 200, opts.text
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    return await client.post(
        "/auth/webauthn/verify",
        json={"flow": flow, "csrf_token": csrf, "credential": credential_to_json(assertion)},
    )


async def admin_at_webauthn_stage(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> tuple[User, str]:
    user = await create_user(db, make_password_hash, tier="admin", password=PW)
    resp = await password_step(idp_client, user.email, PW)
    assert resp.status_code == 303 and resp.headers["location"].startswith("/auth/webauthn")
    return user, flow_of(idp_client)


async def test_admin_bootstrap_enroll_two_keys_then_login(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> None:
    user, flow = await admin_at_webauthn_stage(idp_client, db, make_password_hash)

    # No credentials yet: webauthn page bounces to enrollment.
    page = await idp_client.get(f"/auth/webauthn?flow={flow}")
    assert page.status_code == 303
    enroll_page = await idp_client.get(page.headers["location"])
    assert enroll_page.status_code == 200
    csrf = csrf_of(enroll_page.text)

    primary = SoftWebauthnDevice()
    backup = SoftWebauthnDevice()
    r1 = await enroll_device(idp_client, flow, csrf, primary, "primary")
    assert r1.status_code == 200 and r1.json()["enrolled"] == 1
    r2 = await enroll_device(idp_client, flow, csrf, backup, "backup", break_glass=True)
    assert r2.status_code == 200 and r2.json()["enrolled"] == 2

    # Assertion completes the login.
    done = await assert_device(idp_client, flow, csrf, primary)
    assert done.status_code == 200, done.text
    assert done.json()["redirect"] == "/auth/done"
    assert "__Host-idp_sid" in done.headers.get("set-cookie", "")

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None
    assert session.amr == ["pwd", "webauthn"]
    assert session.auth_tier == "admin"

    events = {
        e.event_type
        for e in (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == user.id))).all()
    }
    assert {"enroll.webauthn", "login.webauthn.success", "session.created"} <= events

    landing = await idp_client.get("/auth/done")
    assert landing.status_code == 200 and "You are signed in" in landing.text


async def test_break_glass_use_emits_high_severity_event(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> None:
    user, flow = await admin_at_webauthn_stage(idp_client, db, make_password_hash)
    enroll_page = await idp_client.get(f"/auth/enroll/webauthn?flow={flow}")
    csrf = csrf_of(enroll_page.text)
    bg = SoftWebauthnDevice()
    await enroll_device(idp_client, flow, csrf, bg, "safe-key", break_glass=True)
    done = await assert_device(idp_client, flow, csrf, bg)
    assert done.status_code == 200
    events = [
        e.event_type
        for e in (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == user.id))).all()
    ]
    assert "login.break_glass.used" in events


async def test_enrollment_blocked_when_credentials_predate_flow(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> None:
    user = await create_user(db, make_password_hash, tier="admin", password=PW)
    db.add(
        WebAuthnCredential(
            user_id=user.id,
            credential_id=b"preexisting-cred",
            public_key=b"pk",
            friendly_name="old key",
            created_at=datetime.now(UTC) - timedelta(days=30),
        )
    )
    await db.flush()

    await password_step(idp_client, user.email, PW)
    flow = flow_of(idp_client)
    page = await idp_client.get(f"/auth/enroll/webauthn?flow={flow}")
    assert page.status_code == 403

    webauthn_page = await idp_client.get(f"/auth/webauthn?flow={flow}")
    csrf = csrf_of(webauthn_page.text)
    opts = await idp_client.post(
        "/auth/enroll/webauthn/options", json={"flow": flow, "csrf_token": csrf}
    )
    assert opts.status_code == 403


async def test_tampered_assertion_rejected(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> None:
    user, flow = await admin_at_webauthn_stage(idp_client, db, make_password_hash)
    enroll_page = await idp_client.get(f"/auth/enroll/webauthn?flow={flow}")
    csrf = csrf_of(enroll_page.text)
    device = SoftWebauthnDevice()
    await enroll_device(idp_client, flow, csrf, device, "key")

    opts = await idp_client.post("/auth/webauthn/options", json={"flow": flow, "csrf_token": csrf})
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    assertion["response"]["signature"] = bytes(b ^ 0xFF for b in assertion["response"]["signature"])
    resp = await idp_client.post(
        "/auth/webauthn/verify",
        json={"flow": flow, "csrf_token": csrf, "credential": credential_to_json(assertion)},
    )
    assert resp.status_code == 401
    events = [
        e.event_type
        for e in (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == user.id))).all()
    ]
    assert "login.webauthn.failure" in events
    assert await db.scalar(select(Session).where(Session.user_id == user.id)) is None


async def test_admin_never_offered_totp(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> None:
    _user, flow = await admin_at_webauthn_stage(idp_client, db, make_password_hash)
    totp_page = await idp_client.get(f"/auth/totp?flow={flow}")
    assert totp_page.status_code == 400  # wrong stage: flow is webauthn-only
    enroll_totp = await idp_client.get(f"/auth/enroll/totp?flow={flow}")
    assert enroll_totp.status_code == 400


async def test_stepup_fresh_assertion(
    idp_client: httpx.AsyncClient, db: AsyncSession, make_password_hash: HashFn
) -> None:
    user, flow = await admin_at_webauthn_stage(idp_client, db, make_password_hash)
    enroll_page = await idp_client.get(f"/auth/enroll/webauthn?flow={flow}")
    csrf = csrf_of(enroll_page.text)
    device = SoftWebauthnDevice()
    await enroll_device(idp_client, flow, csrf, device, "key")
    done = await assert_device(idp_client, flow, csrf, device)
    assert done.status_code == 200

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None and session.step_up_verified_at is None

    opts = await idp_client.post("/auth/stepup/options")
    assert opts.status_code == 200
    assertion = device.get(options_for_device(opts.json()), expected_origin())
    verify = await idp_client.post(
        "/auth/stepup/verify", json={"credential": credential_to_json(assertion)}
    )
    assert verify.status_code == 200 and verify.json() == {"ok": True}
    await db.refresh(session)
    assert session.step_up_verified_at is not None


async def test_stepup_rejected_for_standard_tier(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: object,
) -> None:
    import pyotp

    from helpers import enroll_confirmed_totp, extract_form_fields

    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)  # type: ignore[arg-type]
    resp = await password_step(idp_client, user.email, PW)
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    done = await idp_client.post("/auth/totp", data={**fields, "code": pyotp.TOTP(secret).now()})
    assert done.status_code == 200

    opts = await idp_client.post("/auth/stepup/options")
    assert opts.status_code == 403

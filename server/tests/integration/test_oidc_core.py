"""OIDC core: authorize -> code -> DPoP token exchange -> userinfo -> refresh
rotation -> reuse detection -> revocation, plus every negative the plan names."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from helpers import (
    DpopClient,
    create_user,
    enroll_confirmed_totp,
    extract_form_fields,
    password_step,
)
from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.crypto import new_token, sha256_b64url
from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import AuthEvent, OAuthClient, RefreshToken, Session, User
from hyproxy.idp.oidc import tokens as token_service

pytestmark = pytest.mark.integration

PW = "pw-oidc-tests"
CLIENT_ID = "test-rp"
REDIRECT_URI = "https://rp.test/callback"
HashFn = Callable[[str], str]


def issuer() -> str:
    return get_settings().issuer.rstrip("/")


@pytest.fixture
async def rp_client(db: AsyncSession, secrets_backend: FileSecretsBackend) -> OAuthClient:
    await key_service.bootstrap_if_empty(db, secrets_backend, datetime.now(UTC))
    client = OAuthClient(client_id=CLIENT_ID, client_name="Test RP", redirect_uris=[REDIRECT_URI])
    db.add(client)
    await db.flush()
    return client


def authorize_params(verifier: str, **overrides: str) -> dict[str, str]:
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": new_token(16),
        "nonce": new_token(16),
        "code_challenge": sha256_b64url(verifier),
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return params


async def login_standard(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
) -> User:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)
    resp = await password_step(idp_client, user.email, PW)
    page = await idp_client.get(resp.headers["location"])
    fields = extract_form_fields(page.text)
    done = await idp_client.post("/auth/totp", data={**fields, "code": pyotp.TOTP(secret).now()})
    assert done.status_code in (200, 303)
    return user


async def get_code(
    idp_client: httpx.AsyncClient, verifier: str, **overrides: str
) -> tuple[str, str]:
    params = authorize_params(verifier, **overrides)
    resp = await idp_client.get("/oidc/authorize", params=params)
    assert resp.status_code == 302, resp.text
    query = parse_qs(urlsplit(resp.headers["location"]).query)
    assert "code" in query, query
    return query["code"][0], query["state"][0]


async def exchange(
    idp_client: httpx.AsyncClient,
    dpop: DpopClient,
    code: str,
    verifier: str,
    *,
    redirect_uri: str = REDIRECT_URI,
    client_id: str = CLIENT_ID,
) -> httpx.Response:
    proof = dpop.proof("POST", f"{issuer()}/oidc/token")
    return await idp_client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
        headers={"DPoP": proof},
    )


async def refresh_call(
    idp_client: httpx.AsyncClient, dpop: DpopClient, refresh_token: str
) -> httpx.Response:
    proof = dpop.proof("POST", f"{issuer()}/oidc/token")
    return await idp_client.post(
        "/oidc/token",
        data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        },
        headers={"DPoP": proof},
    )


async def userinfo_call(
    idp_client: httpx.AsyncClient, dpop: DpopClient, access_token: str
) -> httpx.Response:
    proof = dpop.proof("GET", f"{issuer()}/oidc/userinfo", access_token=access_token)
    return await idp_client.get(
        "/oidc/userinfo",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": proof},
    )


# --- authorize validation ------------------------------------------------------


async def test_unknown_client_renders_local_error(
    idp_client: httpx.AsyncClient, rp_client: OAuthClient
) -> None:
    resp = await idp_client.get(
        "/oidc/authorize", params=authorize_params(new_token(32), client_id="ghost")
    )
    assert resp.status_code == 400
    assert "location" not in resp.headers


@pytest.mark.parametrize(
    "bad_uri",
    [
        "https://rp.test/callback/",  # trailing slash
        "https://RP.test/callback",  # case
        "https://rp.test/callback?x=1",  # added query
        "http://rp.test/callback",  # scheme downgrade
    ],
)
async def test_redirect_uri_exact_match(
    idp_client: httpx.AsyncClient, rp_client: OAuthClient, bad_uri: str
) -> None:
    resp = await idp_client.get(
        "/oidc/authorize", params=authorize_params(new_token(32), redirect_uri=bad_uri)
    )
    assert resp.status_code == 400
    assert "location" not in resp.headers


async def test_missing_nonce_and_state_and_plain_pkce_rejected(
    idp_client: httpx.AsyncClient, rp_client: OAuthClient
) -> None:
    verifier = new_token(32)
    # No state: refused via redirect without state.
    p = authorize_params(verifier)
    del p["state"]
    resp = await idp_client.get("/oidc/authorize", params=p)
    assert resp.status_code == 302 and "error=invalid_request" in resp.headers["location"]

    p = authorize_params(verifier)
    del p["nonce"]
    resp = await idp_client.get("/oidc/authorize", params=p)
    assert resp.status_code == 302 and "error=invalid_request" in resp.headers["location"]

    p = authorize_params(verifier, code_challenge_method="plain")
    resp = await idp_client.get("/oidc/authorize", params=p)
    assert resp.status_code == 302 and "error=invalid_request" in resp.headers["location"]

    p = authorize_params(verifier, scope="profile")  # missing openid
    resp = await idp_client.get("/oidc/authorize", params=p)
    assert resp.status_code == 302 and "error=invalid_scope" in resp.headers["location"]


async def test_unauthenticated_authorize_parks_request_in_flow(
    idp_client: httpx.AsyncClient, rp_client: OAuthClient
) -> None:
    resp = await idp_client.get("/oidc/authorize", params=authorize_params(new_token(32)))
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/auth/login?flow=")


async def test_parked_authorize_resumes_after_login(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)

    parked = await idp_client.get("/oidc/authorize", params=authorize_params(new_token(48)))
    assert parked.status_code == 303
    login_loc = parked.headers["location"]
    assert login_loc.startswith("/auth/login?flow=")

    page = await idp_client.get(login_loc)
    fields = extract_form_fields(page.text)
    pw = await idp_client.post(
        "/auth/login", data={**fields, "email": user.email, "password": PW}
    )
    assert pw.status_code == 303
    totp_page = await idp_client.get(pw.headers["location"])
    tfields = extract_form_fields(totp_page.text)

    done = await idp_client.post("/auth/totp", data={**tfields, "code": pyotp.TOTP(secret).now()})
    # Completing the second factor must resume the parked authorize, not dead-end
    # on the signed-in page.
    assert done.status_code == 303, done.text
    assert done.headers["location"].startswith("/oidc/authorize"), done.headers["location"]


async def test_parked_oidc_request_survives_forwarded_ip_change(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hyproxy.config import get_settings

    settings = get_settings().model_copy(update={"trust_forwarded_for": True})
    monkeypatch.setattr("hyproxy.core.netutil.get_settings", lambda: settings)

    user = await create_user(db, make_password_hash, tier="standard", password=PW)
    secret = await enroll_confirmed_totp(db, secrets_backend, user)
    ip_a = {"X-Forwarded-For": "203.0.113.10"}
    ip_b = {"X-Forwarded-For": "203.0.113.20"}

    # Park the request from one client IP, then finish the login from another
    # (as happens when the authorize hop and the login hops resolve the client
    # IP inconsistently). The OIDC continuation must not be lost.
    parked = await idp_client.get(
        "/oidc/authorize", params=authorize_params(new_token(48)), headers=ip_a
    )
    assert parked.status_code == 303
    page = await idp_client.get(parked.headers["location"], headers=ip_b)
    fields = extract_form_fields(page.text)
    pw = await idp_client.post(
        "/auth/login", data={**fields, "email": user.email, "password": PW}, headers=ip_b
    )
    assert pw.status_code == 303
    totp_page = await idp_client.get(pw.headers["location"], headers=ip_b)
    tfields = extract_form_fields(totp_page.text)
    done = await idp_client.post(
        "/auth/totp", data={**tfields, "code": pyotp.TOTP(secret).now()}, headers=ip_b
    )
    assert done.status_code == 303, done.text
    assert done.headers["location"].startswith("/oidc/authorize"), done.headers["location"]


# --- full code + token flow ----------------------------------------------------


async def test_full_code_flow_with_dpop(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _state = await get_code(idp_client, verifier)

    dpop = DpopClient()
    resp = await exchange(idp_client, dpop, code, verifier)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "DPoP"
    assert body["expires_in"] == get_settings().access_ttl
    assert body["scope"] == "openid profile email"

    claims = await token_service.verify_access_token(
        db, token=body["access_token"], now=datetime.now(UTC)
    )
    assert claims.jkt == dpop.jkt
    assert claims.sub == user.external_id
    assert claims.auth_tier == "standard"

    session = await db.get(Session, claims.sid)
    # DPoP binding lives on the issued token (claims.jkt) and the refresh family,
    # not the session, so one session can serve multiple clients/keys.
    assert session is not None
    assert session.dpop_jkt is None

    ui = await userinfo_call(idp_client, dpop, body["access_token"])
    assert ui.status_code == 200
    assert ui.json()["sub"] == user.external_id
    assert ui.json()["email"] == user.email


async def test_code_single_use_replay_revokes_session(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    dpop = DpopClient()
    assert (await exchange(idp_client, dpop, code, verifier)).status_code == 200

    replay = await exchange(idp_client, DpopClient(), code, verifier)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None and session.revoked_at is not None
    assert session.revoke_reason == "auth_code_replay"
    events = [
        e.event_type
        for e in (await db.scalars(select(AuthEvent).where(AuthEvent.user_id == user.id))).all()
    ]
    assert "oidc.code.replay_detected" in events


async def test_wrong_pkce_verifier_rejected(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    resp = await exchange(idp_client, DpopClient(), code, new_token(48))
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"


async def test_token_redirect_uri_must_match_code(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    resp = await exchange(idp_client, DpopClient(), code, verifier, redirect_uri=REDIRECT_URI + "/")
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"


async def test_missing_dpop_header_rejected(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    resp = await idp_client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_dpop_proof"


# --- refresh rotation ------------------------------------------------------------


async def test_refresh_rotation_and_reuse_detection(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    dpop = DpopClient()
    first = (await exchange(idp_client, dpop, code, verifier)).json()

    rotated = await refresh_call(idp_client, dpop, first["refresh_token"])
    assert rotated.status_code == 200
    second = rotated.json()
    assert second["refresh_token"] != first["refresh_token"]

    # jkt continuity: the new access token is bound to the same key.
    claims = await token_service.verify_access_token(
        db, token=second["access_token"], now=datetime.now(UTC)
    )
    assert claims.jkt == dpop.jkt

    # Reusing the first (already rotated) refresh token kills family + session.
    reuse = await refresh_call(idp_client, dpop, first["refresh_token"])
    assert reuse.status_code == 400 and reuse.json()["error"] == "invalid_grant"

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None and session.revoke_reason == "refresh_reuse"
    family = (await db.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id))).all()
    assert all(t.revoked_at is not None or t.used_at is not None for t in family)

    # And the still-newest token is dead too because its family was revoked.
    after = await refresh_call(idp_client, dpop, second["refresh_token"])
    assert after.status_code == 400


async def test_refresh_with_wrong_dpop_key_rejected(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    body = (await exchange(idp_client, DpopClient(), code, verifier)).json()
    resp = await refresh_call(idp_client, DpopClient(), body["refresh_token"])
    assert resp.status_code == 400 and resp.json()["error"] == "invalid_grant"


# --- session semantics ------------------------------------------------------------


async def test_ip_change_marks_session_stale(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    dpop = DpopClient()
    body = (await exchange(idp_client, dpop, code, verifier)).json()

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None
    session.source_ip = "198.51.100.99"  # simulate the user's IP changing
    await db.flush()

    ui = await userinfo_call(idp_client, dpop, body["access_token"])
    assert ui.status_code == 401
    await db.refresh(session)
    assert session.stale is True

    # Refresh dies the same way: full re-auth required.
    resp = await refresh_call(idp_client, dpop, body["refresh_token"])
    assert resp.status_code == 400


async def test_token_exchange_ignores_caller_ip(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    """The token endpoint's caller is the OAuth client's server-side backchannel
    (e.g. the gateway), not the browser, so its socket IP never matches the
    session's. A differing IP must not fail the code exchange or mark the session
    stale. Regression: gateway resource login failed with 'sign-in failed'."""
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None
    session.source_ip = "203.0.113.7"  # session bound to the browser IP...
    await db.flush()

    dpop = DpopClient()
    resp = await exchange(idp_client, dpop, code, verifier)  # ...exchanged from a different IP
    assert resp.status_code == 200, resp.text

    await db.refresh(session)
    assert session.stale is False


async def test_multiple_dpop_keys_on_one_session(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    """One IdP session serves several OIDC clients (e.g. the admin SPA and the
    gateway), each with its own DPoP key. Successive code exchanges on that
    session must not pin it to a single key. Regression: after the gateway
    exchanged on the session, admin login failed with invalid_grant."""
    await login_standard(idp_client, db, make_password_hash, secrets_backend)

    v1 = new_token(48)
    code1, _ = await get_code(idp_client, v1)
    r1 = await exchange(idp_client, DpopClient(), code1, v1)
    assert r1.status_code == 200, r1.text

    # Same session, a second client presenting a DIFFERENT DPoP key.
    v2 = new_token(48)
    code2, _ = await get_code(idp_client, v2)
    r2 = await exchange(idp_client, DpopClient(), code2, v2)
    assert r2.status_code == 200, r2.text


async def test_idle_timeout_kills_refresh(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    dpop = DpopClient()
    body = (await exchange(idp_client, dpop, code, verifier)).json()

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None
    session.last_seen_at = datetime.now(UTC) - timedelta(minutes=31)
    await db.flush()

    resp = await refresh_call(idp_client, dpop, body["refresh_token"])
    assert resp.status_code == 400
    await db.refresh(session)
    assert session.revoke_reason == "idle_timeout"


async def test_absolute_expiry_kills_refresh_independently(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    dpop = DpopClient()
    body = (await exchange(idp_client, dpop, code, verifier)).json()

    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None
    session.absolute_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    session.last_seen_at = datetime.now(UTC)  # idle timeout NOT tripped
    await db.flush()

    resp = await refresh_call(idp_client, dpop, body["refresh_token"])
    assert resp.status_code == 400


async def test_userinfo_negatives(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    dpop = DpopClient()
    body = (await exchange(idp_client, dpop, code, verifier)).json()
    token = body["access_token"]

    # Proof from a different key than cnf.jkt.
    stranger = DpopClient()
    proof = stranger.proof("GET", f"{issuer()}/oidc/userinfo", access_token=token)
    resp = await idp_client.get(
        "/oidc/userinfo", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert resp.status_code == 401
    assert 'error="invalid_dpop_proof"' in resp.headers["www-authenticate"]

    # Bearer scheme is not accepted.
    resp = await idp_client.get("/oidc/userinfo", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401

    # Garbage token.
    proof = dpop.proof("GET", f"{issuer()}/oidc/userinfo", access_token="junk")
    resp = await idp_client.get(
        "/oidc/userinfo", headers={"Authorization": "DPoP junk", "DPoP": proof}
    )
    assert resp.status_code == 401


async def test_revoke_endpoint(
    idp_client: httpx.AsyncClient,
    db: AsyncSession,
    make_password_hash: HashFn,
    secrets_backend: FileSecretsBackend,
    rp_client: OAuthClient,
) -> None:
    user = await login_standard(idp_client, db, make_password_hash, secrets_backend)
    verifier = new_token(48)
    code, _ = await get_code(idp_client, verifier)
    dpop = DpopClient()
    body = (await exchange(idp_client, dpop, code, verifier)).json()

    # Wrong-key revocation is a no-op (but still 200, no oracle).
    stranger = DpopClient()
    resp = await idp_client.post(
        "/oidc/revoke",
        data={"token": body["refresh_token"]},
        headers={"DPoP": stranger.proof("POST", f"{issuer()}/oidc/revoke")},
    )
    assert resp.status_code == 200
    session = await db.scalar(select(Session).where(Session.user_id == user.id))
    assert session is not None and session.revoked_at is None

    # Correct-key revocation kills family and session.
    resp = await idp_client.post(
        "/oidc/revoke",
        data={"token": body["refresh_token"]},
        headers={"DPoP": dpop.proof("POST", f"{issuer()}/oidc/revoke")},
    )
    assert resp.status_code == 200
    await db.refresh(session)
    assert session.revoked_at is not None

    ui = await userinfo_call(idp_client, dpop, body["access_token"])
    assert ui.status_code == 401  # immediate revocation via the session lookup

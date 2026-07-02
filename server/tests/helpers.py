"""Shared test helpers (on pytest's pythonpath via pyproject)."""

import base64
import json
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
from joserfc import jws
from joserfc.jwk import ECKey
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.core.secrets import FileSecretsBackend
from hyproxy.db.models import User
from hyproxy.security import totp as totp_service


class DpopClient:
    """Test stand-in for the browser's WebCrypto DPoP keypair."""

    def __init__(self) -> None:
        self.key = ECKey.generate_key("P-256", private=True)

    @property
    def jkt(self) -> str:
        return self.key.thumbprint()

    def public_jwk(self) -> dict[str, Any]:
        return self.key.as_dict(private=False)

    def proof(
        self,
        htm: str,
        htu: str,
        *,
        access_token: str | None = None,
        typ: str | None = "dpop+jwt",
        jti: str | None = None,
        iat: int | None = None,
        jwk_override: dict[str, Any] | None = None,
        extra_claims: dict[str, Any] | None = None,
        omit: set[str] | None = None,
    ) -> str:
        header: dict[str, Any] = {
            "typ": typ,
            "alg": "ES256",
            "jwk": jwk_override if jwk_override is not None else self.public_jwk(),
        }
        if typ is None:
            del header["typ"]
        claims: dict[str, Any] = {
            "jti": jti if jti is not None else uuid.uuid4().hex,
            "htm": htm,
            "htu": htu,
            "iat": iat if iat is not None else int(time.time()),
        }
        if access_token is not None:
            from hyproxy.idp.oidc.dpop import ath_of

            claims["ath"] = ath_of(access_token)
        if extra_claims:
            claims.update(extra_claims)
        for name in omit or set():
            claims.pop(name, None)
        return jws.serialize_compact(header, json.dumps(claims).encode(), self.key)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def extract_form_fields(html: str) -> dict[str, str]:
    return dict(re.findall(r'name="(\w+)" value="([^"]*)"', html))


def extract_block_values(html: str) -> list[str]:
    return re.findall(r'<code class="block">([^<]+)</code>', html)


async def create_user(
    db: AsyncSession,
    make_password_hash: Callable[[str], str],
    *,
    tier: str,
    password: str,
    status: str = "active",
) -> User:
    user = User(
        external_id=f"u-{uuid.uuid4()}",
        email=f"{uuid.uuid4()}@example.test",
        display_name="Test",
        status=status,
        auth_tier=tier,
        password_hash=make_password_hash(password),
    )
    db.add(user)
    await db.flush()
    return user


async def enroll_confirmed_totp(db: AsyncSession, backend: FileSecretsBackend, user: User) -> str:
    """Give the user a confirmed TOTP secret; returns the plaintext secret."""
    secret = totp_service.generate_secret()
    row = await totp_service.store_pending_secret(db, backend, user.id, secret)
    row.confirmed_at = datetime.now(UTC)
    await db.flush()
    return secret


async def start_login(client: httpx.AsyncClient) -> dict[str, str]:
    resp = await client.get("/auth/login")
    assert resp.status_code == 200
    return extract_form_fields(resp.text)


async def password_step(client: httpx.AsyncClient, email: str, password: str) -> httpx.Response:
    fields = await start_login(client)
    return await client.post("/auth/login", data={**fields, "email": email, "password": password})


# --- WebAuthn helpers (soft-webauthn speaks browser-style raw bytes) ----------


def _b64u_decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64u_encode(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def options_for_device(options: dict) -> dict:  # type: ignore[type-arg]
    """Convert server options JSON (b64url strings) to the browser-API shape."""
    out = dict(options)
    out["challenge"] = _b64u_decode(out["challenge"])
    if "user" in out:
        out["user"] = {**out["user"], "id": _b64u_decode(out["user"]["id"])}
    for key in ("allowCredentials", "excludeCredentials"):
        if out.get(key):
            out[key] = [{**c, "id": _b64u_decode(c["id"])} for c in out[key]]
    return {"publicKey": out}


def credential_to_json(cred: dict) -> dict:  # type: ignore[type-arg]
    """Convert a soft-webauthn credential (raw bytes) to the JSON the server expects."""
    response = {}
    for key, value in cred["response"].items():
        response[key] = _b64u_encode(value) if isinstance(value, bytes) else value
    raw_id = cred["rawId"]
    raw_id_b64u = _b64u_encode(raw_id) if isinstance(raw_id, bytes) else raw_id
    return {
        "id": raw_id_b64u,  # per spec, id is the b64url of rawId
        "rawId": raw_id_b64u,
        "type": cred["type"],
        "response": response,
        "clientExtensionResults": {},
    }

"""Access and ID token mint/verify (ES256 JWTs via joserfc).

Access tokens are short-lived and carry cnf.jkt (DPoP binding) plus sid so
every consumer can (must) do the session liveness lookup. Verification
accepts the active and retiring signing keys (publish-overlap-retire).
"""

import base64
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from joserfc import jwt as joserfc_jwt
from joserfc.errors import JoseError
from joserfc.jwk import ECKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core import keys as key_service
from hyproxy.core.secrets import SecretsBackend
from hyproxy.db.models import Session, SigningKey, User


class TokenError(Exception):
    """Any access-token validation failure; maps to 401 invalid_token."""


@dataclass(frozen=True)
class AccessClaims:
    sub: str
    aud: str
    sid: uuid.UUID
    scope: str
    auth_tier: str
    amr: list[str]
    jkt: str
    jti: str
    exp: datetime


async def mint_access_token(
    db: AsyncSession,
    backend: SecretsBackend,
    *,
    user: User,
    session: Session,
    client_id: str,
    scope: str,
    jkt: str,
    now: datetime,
) -> str:
    settings = get_settings()
    kid, key = await key_service.get_active_signing_key(db, backend)
    claims = {
        "iss": settings.issuer.rstrip("/"),
        "sub": user.external_id,
        "aud": client_id,
        "exp": int((now + timedelta(seconds=settings.access_ttl)).timestamp()),
        "iat": int(now.timestamp()),
        "jti": uuid.uuid4().hex,
        "sid": str(session.id),
        "scope": scope,
        "auth_tier": session.auth_tier,
        "amr": session.amr,
        "cnf": {"jkt": jkt},
    }
    return joserfc_jwt.encode({"alg": "ES256", "kid": kid, "typ": "at+jwt"}, claims, key)


async def mint_id_token(
    db: AsyncSession,
    backend: SecretsBackend,
    *,
    user: User,
    session: Session,
    client_id: str,
    nonce: str,
    auth_time: datetime,
    now: datetime,
) -> str:
    settings = get_settings()
    kid, key = await key_service.get_active_signing_key(db, backend)
    claims = {
        "iss": settings.issuer.rstrip("/"),
        "sub": user.external_id,
        "aud": client_id,
        "exp": int((now + timedelta(seconds=settings.access_ttl)).timestamp()),
        "iat": int(now.timestamp()),
        "auth_time": int(auth_time.timestamp()),
        "nonce": nonce,
        "amr": session.amr,
        "acr": f"tier:{session.auth_tier}",
        "sid": str(session.id),
    }
    return joserfc_jwt.encode({"alg": "ES256", "kid": kid, "typ": "JWT"}, claims, key)


def _header_of(token: str) -> dict[str, Any]:
    try:
        segment = token.split(".")[0]
        parsed = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, IndexError) as exc:
        raise TokenError("malformed token") from exc
    if not isinstance(parsed, dict):
        raise TokenError("malformed token header")
    return parsed


async def verify_id_token(
    db: AsyncSession, *, token: str, client_id: str, now: datetime
) -> dict[str, Any]:
    """Signature/iss/aud/exp validation for an ID token (RP side of the
    gateway). Returns the claims dict; nonce checking is the caller's job."""
    header = _header_of(token)
    if header.get("alg") != "ES256":
        raise TokenError("bad alg")
    kid = header.get("kid")
    row = await db.scalar(
        select(SigningKey).where(
            SigningKey.kid == str(kid), SigningKey.state.in_(("active", "retiring"))
        )
    )
    if row is None:
        raise TokenError("unknown or retired signing key")
    key = ECKey.import_key(row.public_jwk)
    try:
        decoded = joserfc_jwt.decode(token, key, algorithms=["ES256"])
    except (JoseError, ValueError) as exc:
        raise TokenError("signature verification failed") from exc
    claims = decoded.claims
    if claims.get("iss") != get_settings().issuer.rstrip("/"):
        raise TokenError("wrong issuer")
    if claims.get("aud") != client_id:
        raise TokenError("wrong audience")
    exp = claims.get("exp")
    if not isinstance(exp, int) or datetime.fromtimestamp(exp, tz=UTC) <= now:
        raise TokenError("expired")
    return dict(claims)


async def verify_access_token(db: AsyncSession, *, token: str, now: datetime) -> AccessClaims:
    header = _header_of(token)
    if header.get("alg") != "ES256":
        raise TokenError("bad alg")
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise TokenError("missing kid")
    row = await db.scalar(
        select(SigningKey).where(
            SigningKey.kid == kid, SigningKey.state.in_(("active", "retiring"))
        )
    )
    if row is None:
        raise TokenError("unknown or retired signing key")
    key = ECKey.import_key(row.public_jwk)
    try:
        decoded = joserfc_jwt.decode(token, key, algorithms=["ES256"])
    except (JoseError, ValueError) as exc:
        raise TokenError("signature verification failed") from exc
    claims = decoded.claims

    if claims.get("iss") != get_settings().issuer.rstrip("/"):
        raise TokenError("wrong issuer")
    exp = claims.get("exp")
    if not isinstance(exp, int) or datetime.fromtimestamp(exp, tz=UTC) <= now:
        raise TokenError("expired")
    cnf = claims.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    sid_raw = claims.get("sid")
    try:
        sid = uuid.UUID(str(sid_raw))
    except ValueError as exc:
        raise TokenError("bad sid") from exc
    if not isinstance(jkt, str):
        raise TokenError("missing cnf.jkt")
    amr = claims.get("amr")
    if not isinstance(amr, list):
        amr = []
    return AccessClaims(
        sub=str(claims.get("sub", "")),
        aud=str(claims.get("aud", "")),
        sid=sid,
        scope=str(claims.get("scope", "")),
        auth_tier=str(claims.get("auth_tier", "")),
        amr=[str(a) for a in amr],
        jkt=jkt,
        jti=str(claims.get("jti", "")),
        exp=datetime.fromtimestamp(exp, tz=UTC),
    )

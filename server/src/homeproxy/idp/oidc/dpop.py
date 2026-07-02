"""DPoP proof validation (RFC 9449).

Pure-function core: every check except replay detection needs no I/O. The
replay cache is injected as a protocol so the validator is unit-testable
without a database.

Check order (each has a dedicated negative test):
 1. compact JWS structure, header typ == "dpop+jwt"
 2. alg in the allowlist {ES256}; never none/HMAC
 3. embedded jwk is a public P-256 EC key: no private members, no x5c/kid
    trust shortcuts
 4. signature verifies against the embedded jwk
 5. claims: jti (8..256 chars), htm matches the request method, htu matches
    the request URL under RFC 9449 normalization, iat inside the freshness
    window
 6. ath == b64url(sha256(access_token)) when an access token is presented
 7. jkt (RFC 7638 thumbprint) equals the expected binding when one applies
 8. jti not seen before for this jkt (replay cache)
"""

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import ECKey

ALLOWED_ALGS = frozenset({"ES256"})
JTI_MIN, JTI_MAX = 8, 256
# JWK members that must not appear in a DPoP proof header key.
FORBIDDEN_JWK_MEMBERS = frozenset(
    {"d", "p", "q", "dp", "dq", "qi", "k", "x5c", "x5u", "x5t", "x5t#S256", "kid"}
)


class DpopError(Exception):
    """Maps to error=invalid_dpop_proof; detail is for logs, never the client."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class JtiReplayCache(Protocol):
    async def check_and_store(self, jkt: str, jti: str, expires_at: datetime) -> bool:
        """True if (jkt, jti) is new and now stored; False on replay."""
        ...


@dataclass(frozen=True)
class DpopProof:
    jkt: str
    jti: str
    iat: datetime


def _b64u_decode(segment: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error) as exc:
        raise DpopError("malformed base64url segment") from exc


def _b64u_json(segment: str) -> dict[str, Any]:
    try:
        parsed = json.loads(_b64u_decode(segment))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DpopError("malformed JSON segment") from exc
    if not isinstance(parsed, dict):
        raise DpopError("segment is not a JSON object")
    return parsed


def normalize_htu(url: str) -> str | None:
    """RFC 9449 htu comparison form: lowercase scheme/host, drop default port,
    drop query and fragment, empty path becomes '/'."""
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not hostname:
        return None
    scheme = parts.scheme.lower()
    host = hostname.lower()
    default = 443 if scheme == "https" else 80
    netloc = host if port is None or port == default else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", "", ""))


def ath_of(access_token: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest())
        .rstrip(b"=")
        .decode()
    )


def verify_proof_offline(
    proof: str,
    *,
    htm: str,
    htu: str,
    now: datetime,
    iat_window: int = 300,
    iat_future_skew: int = 30,
    access_token: str | None = None,
    expected_jkt: str | None = None,
) -> DpopProof:
    """All checks except replay. Raises DpopError on any failure."""
    parts = proof.split(".")
    if len(parts) != 3 or not all(parts):
        raise DpopError("not a compact JWS")

    header = _b64u_json(parts[0])
    if header.get("typ") != "dpop+jwt":
        raise DpopError("typ must be dpop+jwt")
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise DpopError(f"alg {alg!r} not allowed")

    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DpopError("missing embedded jwk")
    present_forbidden = FORBIDDEN_JWK_MEMBERS & set(jwk)
    if present_forbidden:
        raise DpopError(f"forbidden jwk members: {sorted(present_forbidden)}")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "x" not in jwk or "y" not in jwk:
        raise DpopError("jwk must be a public P-256 EC key")
    try:
        key = ECKey.import_key(jwk)
    except (JoseError, ValueError) as exc:
        raise DpopError("invalid jwk") from exc

    try:
        verified = jws.deserialize_compact(proof, key, algorithms=list(ALLOWED_ALGS))
    except JoseError as exc:
        raise DpopError("signature verification failed") from exc
    claims = json.loads(verified.payload)
    if not isinstance(claims, dict):
        raise DpopError("claims must be a JSON object")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not (JTI_MIN <= len(jti) <= JTI_MAX):
        raise DpopError("invalid jti")

    if claims.get("htm") != htm:
        raise DpopError("htm mismatch")

    claimed_htu = claims.get("htu")
    if not isinstance(claimed_htu, str):
        raise DpopError("missing htu")
    normalized_claim = normalize_htu(claimed_htu)
    normalized_actual = normalize_htu(htu)
    if normalized_claim is None or normalized_actual is None:
        raise DpopError("unnormalizable htu")
    if normalized_claim != normalized_actual:
        raise DpopError("htu mismatch")

    iat = claims.get("iat")
    if not isinstance(iat, int):
        raise DpopError("missing iat")
    iat_dt = datetime.fromtimestamp(iat, tz=UTC)
    if iat_dt < now - timedelta(seconds=iat_window):
        raise DpopError("stale iat")
    if iat_dt > now + timedelta(seconds=iat_future_skew):
        raise DpopError("iat in the future")

    if access_token is not None:
        ath = claims.get("ath")
        if not isinstance(ath, str) or not hmac.compare_digest(
            ath.encode(), ath_of(access_token).encode()
        ):
            raise DpopError("ath mismatch")

    jkt = key.thumbprint()
    if expected_jkt is not None and not hmac.compare_digest(jkt.encode(), expected_jkt.encode()):
        raise DpopError("jkt does not match token binding")

    return DpopProof(jkt=jkt, jti=jti, iat=iat_dt)


async def verify_proof(
    proof: str,
    *,
    htm: str,
    htu: str,
    now: datetime,
    replay_cache: JtiReplayCache,
    iat_window: int = 300,
    iat_future_skew: int = 30,
    access_token: str | None = None,
    expected_jkt: str | None = None,
) -> DpopProof:
    """Full validation including replay detection."""
    result = verify_proof_offline(
        proof,
        htm=htm,
        htu=htu,
        now=now,
        iat_window=iat_window,
        iat_future_skew=iat_future_skew,
        access_token=access_token,
        expected_jkt=expected_jkt,
    )
    fresh = await replay_cache.check_and_store(
        result.jkt, result.jti, now + timedelta(seconds=iat_window)
    )
    if not fresh:
        raise DpopError("jti replay")
    return result

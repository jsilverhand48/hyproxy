"""PKCE S256 verification (RFC 7636). Plain method is not supported."""

import hmac
import re

from hyproxy.core.crypto import sha256_b64url

# RFC 7636 section 4.1: unreserved characters, 43..128 chars.
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9\-_]{43,128}$")


def valid_challenge(challenge: str) -> bool:
    return bool(_CHALLENGE_RE.match(challenge))


def verify_s256(verifier: str, challenge: str) -> bool:
    if not _VERIFIER_RE.match(verifier) or not valid_challenge(challenge):
        return False
    return hmac.compare_digest(sha256_b64url(verifier).encode(), challenge.encode())

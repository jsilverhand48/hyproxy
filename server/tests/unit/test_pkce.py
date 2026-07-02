from hypothesis import given
from hypothesis import strategies as st

from hyproxy.core.crypto import sha256_b64url
from hyproxy.security.pkce import valid_challenge, verify_s256

VERIFIER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

verifiers = st.text(alphabet=VERIFIER_ALPHABET, min_size=43, max_size=128)


@given(verifier=verifiers)
def test_s256_roundtrip(verifier: str) -> None:
    assert verify_s256(verifier, sha256_b64url(verifier))


@given(verifier=verifiers, flip=st.integers(min_value=0, max_value=42))
def test_mutated_verifier_fails(verifier: str, flip: int) -> None:
    challenge = sha256_b64url(verifier)
    mutated = verifier[:flip] + ("A" if verifier[flip] != "A" else "B") + verifier[flip + 1 :]
    assert not verify_s256(mutated, challenge)


def test_rfc7636_appendix_b_vector() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert verify_s256(verifier, challenge)


def test_verifier_length_bounds() -> None:
    challenge = sha256_b64url("x" * 43)
    assert not verify_s256("x" * 42, challenge)
    assert not verify_s256("x" * 129, challenge)


def test_verifier_charset_enforced() -> None:
    bad = "!" * 50
    assert not verify_s256(bad, sha256_b64url(bad))


def test_challenge_shape() -> None:
    assert valid_challenge(sha256_b64url("some-verifier-value-that-is-long-enough-ok"))
    assert not valid_challenge("short")
    assert not valid_challenge("has+plus/" + "a" * 40)

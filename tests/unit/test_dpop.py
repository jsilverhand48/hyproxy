import base64
import json
import time
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from helpers import DpopClient, b64u
from hyproxy.idp.oidc.dpop import (
    DpopError,
    ath_of,
    normalize_htu,
    verify_proof,
    verify_proof_offline,
)

NOW = datetime.now(UTC)
HTM = "POST"
HTU = "https://idp.localhost:8300/oidc/token"


@pytest.fixture(scope="module")
def client() -> DpopClient:
    return DpopClient()


def verify(proof: str, **kwargs: object) -> object:
    defaults: dict[str, object] = {"htm": HTM, "htu": HTU, "now": NOW}
    defaults.update(kwargs)
    return verify_proof_offline(proof, **defaults)  # type: ignore[arg-type]


def test_valid_proof_passes(client: DpopClient) -> None:
    result = verify(client.proof(HTM, HTU))
    assert result.jkt == client.jkt  # type: ignore[attr-defined]


def test_not_a_jws() -> None:
    for bad in ("", "a.b", "a.b.c.d", "..", "a..c"):
        with pytest.raises(DpopError):
            verify(bad)


def test_wrong_typ(client: DpopClient) -> None:
    with pytest.raises(DpopError, match="typ"):
        verify(client.proof(HTM, HTU, typ="jwt"))
    with pytest.raises(DpopError, match="typ"):
        verify(client.proof(HTM, HTU, typ=None))


def test_alg_none_rejected(client: DpopClient) -> None:
    header = b64u(
        json.dumps({"typ": "dpop+jwt", "alg": "none", "jwk": client.public_jwk()}).encode()
    )
    payload = b64u(
        json.dumps({"jti": "x" * 16, "htm": HTM, "htu": HTU, "iat": int(time.time())}).encode()
    )
    with pytest.raises(DpopError, match="alg"):
        verify(f"{header}.{payload}.{b64u(b'sig')}")


def test_alg_hs256_rejected(client: DpopClient) -> None:
    header = b64u(
        json.dumps({"typ": "dpop+jwt", "alg": "HS256", "jwk": client.public_jwk()}).encode()
    )
    payload = b64u(
        json.dumps({"jti": "x" * 16, "htm": HTM, "htu": HTU, "iat": int(time.time())}).encode()
    )
    with pytest.raises(DpopError, match="alg"):
        verify(f"{header}.{payload}.{b64u(b'sig')}")


def test_private_jwk_member_rejected(client: DpopClient) -> None:
    private_jwk = client.key.as_dict(private=True)
    with pytest.raises(DpopError, match="forbidden"):
        verify(client.proof(HTM, HTU, jwk_override=private_jwk))


def test_kid_and_x5c_shortcuts_rejected(client: DpopClient) -> None:
    for member in ("kid", "x5c"):
        jwk = client.public_jwk() | {member: "value"}
        with pytest.raises(DpopError, match="forbidden"):
            verify(client.proof(HTM, HTU, jwk_override=jwk))


def test_non_p256_key_rejected(client: DpopClient) -> None:
    with pytest.raises(DpopError, match="P-256"):
        verify(client.proof(HTM, HTU, jwk_override={"kty": "RSA", "n": "AQAB", "e": "AQAB"}))


def test_bad_signature_rejected(client: DpopClient) -> None:
    proof = client.proof(HTM, HTU)
    head, payload, sig = proof.split(".")
    other = json.loads(base64.urlsafe_b64decode(payload + "=="))
    other["htm"] = HTM  # same content, re-encoded differently would break sig anyway
    other["jti"] = "tampered-jti-value"
    tampered_payload = b64u(json.dumps(other).encode())
    with pytest.raises(DpopError, match="signature"):
        verify(f"{head}.{tampered_payload}.{sig}")


def test_signature_from_other_key_rejected(client: DpopClient) -> None:
    other = DpopClient()
    proof = other.proof(HTM, HTU)
    _head, payload, sig = proof.split(".")
    fake_head = b64u(
        json.dumps({"typ": "dpop+jwt", "alg": "ES256", "jwk": client.public_jwk()}).encode()
    )
    with pytest.raises(DpopError, match="signature"):
        verify(f"{fake_head}.{payload}.{sig}")


def test_jti_bounds(client: DpopClient) -> None:
    with pytest.raises(DpopError, match="jti"):
        verify(client.proof(HTM, HTU, jti="short"))
    with pytest.raises(DpopError, match="jti"):
        verify(client.proof(HTM, HTU, jti="x" * 300))
    with pytest.raises(DpopError, match="jti"):
        verify(client.proof(HTM, HTU, omit={"jti"}))


def test_htm_mismatch(client: DpopClient) -> None:
    with pytest.raises(DpopError, match="htm"):
        verify(client.proof("GET", HTU))
    # htm is case-sensitive uppercase per the HTTP method
    with pytest.raises(DpopError, match="htm"):
        verify(client.proof("post", HTU))


def test_htu_mismatch_path_and_host(client: DpopClient) -> None:
    with pytest.raises(DpopError, match="htu"):
        verify(client.proof(HTM, "https://idp.localhost:8300/oidc/other"))
    with pytest.raises(DpopError, match="htu"):
        verify(client.proof(HTM, "https://evil.example/oidc/token"))


def test_htu_normalization_equivalences(client: DpopClient) -> None:
    # Query and fragment are ignored; scheme/host case-folded; default port dropped.
    verify(client.proof(HTM, HTU + "?foo=bar#frag"))
    verify(client.proof(HTM, "HTTPS://IDP.LOCALHOST:8300/oidc/token"))
    verify(
        client.proof(HTM, "https://idp.localhost/oidc/token"),
        htu="https://idp.localhost:443/oidc/token",
    )


def test_missing_htu(client: DpopClient) -> None:
    with pytest.raises(DpopError, match="htu"):
        verify(client.proof(HTM, HTU, omit={"htu"}))


def test_iat_window(client: DpopClient) -> None:
    now_ts = int(NOW.timestamp())
    with pytest.raises(DpopError, match="stale"):
        verify(client.proof(HTM, HTU, iat=now_ts - 301))
    with pytest.raises(DpopError, match="future"):
        verify(client.proof(HTM, HTU, iat=now_ts + 31))
    verify(client.proof(HTM, HTU, iat=now_ts - 299))
    verify(client.proof(HTM, HTU, iat=now_ts + 29))
    with pytest.raises(DpopError, match="iat"):
        verify(client.proof(HTM, HTU, omit={"iat"}))


def test_ath_binding(client: DpopClient) -> None:
    token = "an.access.token"
    verify(client.proof(HTM, HTU, access_token=token), access_token=token)
    with pytest.raises(DpopError, match="ath"):
        verify(client.proof(HTM, HTU), access_token=token)  # missing ath
    with pytest.raises(DpopError, match="ath"):
        verify(
            client.proof(HTM, HTU, access_token="different.token"),
            access_token=token,
        )


def test_expected_jkt_binding(client: DpopClient) -> None:
    verify(client.proof(HTM, HTU), expected_jkt=client.jkt)
    other = DpopClient()
    with pytest.raises(DpopError, match="jkt"):
        verify(other.proof(HTM, HTU), expected_jkt=client.jkt)


class FakeCache:
    def __init__(self, fresh: bool) -> None:
        self.fresh = fresh
        self.calls: list[tuple[str, str]] = []

    async def check_and_store(self, jkt: str, jti: str, expires_at: datetime) -> bool:
        self.calls.append((jkt, jti))
        return self.fresh


async def test_replay_detected(client: DpopClient) -> None:
    cache = FakeCache(fresh=False)
    with pytest.raises(DpopError, match="replay"):
        await verify_proof(client.proof(HTM, HTU), htm=HTM, htu=HTU, now=NOW, replay_cache=cache)
    assert cache.calls  # replay check ran after all offline checks passed


async def test_fresh_jti_accepted(client: DpopClient) -> None:
    cache = FakeCache(fresh=True)
    result = await verify_proof(
        client.proof(HTM, HTU), htm=HTM, htu=HTU, now=NOW, replay_cache=cache
    )
    assert result.jkt == client.jkt


def test_ath_of_rfc_shape() -> None:
    digest = ath_of("token")
    assert "=" not in digest and "+" not in digest and "/" not in digest


# --- Hypothesis: htu normalization properties ---------------------------------

hosts = st.from_regex(r"[a-zA-Z]([a-zA-Z0-9\-]{0,20}[a-zA-Z0-9])?", fullmatch=True)
paths = st.from_regex(r"(/[a-zA-Z0-9._~\-]{0,10}){0,4}", fullmatch=True)
schemes = st.sampled_from(["http", "https", "HTTP", "HTTPS", "Https"])
ports = st.one_of(st.none(), st.integers(min_value=1, max_value=65535))
queries = st.one_of(st.none(), st.from_regex(r"[a-z0-9=&]{0,20}", fullmatch=True))


@given(scheme=schemes, host=hosts, port=ports, path=paths, query=queries)
def test_normalize_htu_idempotent_and_query_free(
    scheme: str, host: str, port: int | None, path: str, query: str | None
) -> None:
    url = f"{scheme}://{host}"
    if port is not None:
        url += f":{port}"
    url += path
    if query is not None:
        url += f"?{query}"
    normalized = normalize_htu(url)
    assert normalized is not None
    assert normalize_htu(normalized) == normalized  # idempotent
    assert "?" not in normalized and "#" not in normalized
    assert normalized.startswith(scheme.lower())


@given(host=hosts, path=paths)
def test_normalize_htu_default_port_equivalence(host: str, path: str) -> None:
    assert normalize_htu(f"https://{host}:443{path}") == normalize_htu(f"https://{host}{path}")
    assert normalize_htu(f"http://{host}:80{path}") == normalize_htu(f"http://{host}{path}")
    assert normalize_htu(f"https://{host}:8443{path}") != normalize_htu(f"https://{host}{path}")


@given(host=hosts, path=paths)
def test_normalize_htu_case_insensitive_host(host: str, path: str) -> None:
    assert normalize_htu(f"https://{host.upper()}{path}") == normalize_htu(
        f"https://{host.lower()}{path}"
    )

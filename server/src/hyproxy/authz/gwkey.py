"""The gateway's server-side DPoP keypair and proof builder.

The gateway is an OAuth client running on the control plane, so its DPoP key
lives server-side (unlike browser RPs, whose keys live in WebCrypto). The key
is derived deterministically from the master key via HKDF so its RFC 7638
thumbprint is stable across restarts; nothing is written to disk.
"""

import json
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from joserfc import jws
from joserfc.jwk import ECKey

from hyproxy.core.secrets import SecretsBackend

# Order of the P-256 group (for reducing HKDF output into a valid scalar).
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def gateway_dpop_key(backend: SecretsBackend) -> ECKey:
    master = backend.get_master_key(backend.current_key_id())
    okm = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"hyproxy-gateway-dpop",
        info=b"v1",
    ).derive(master)
    scalar = (int.from_bytes(okm) % (_P256_ORDER - 1)) + 1
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return ECKey.import_key(pem.decode())


def make_proof(key: ECKey, htm: str, htu: str, access_token: str | None = None) -> str:
    header: dict[str, Any] = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": key.as_dict(private=False),
    }
    claims: dict[str, Any] = {
        "jti": uuid.uuid4().hex,
        "htm": htm,
        "htu": htu,
        "iat": int(time.time()),
    }
    if access_token is not None:
        from hyproxy.idp.oidc.dpop import ath_of

        claims["ath"] = ath_of(access_token)
    return jws.serialize_compact(header, json.dumps(claims).encode(), key)

"""Reference relying party used by the end-to-end tests.

This models exactly what the browser-based RP frontend does in production:
generate a non-extractable DPoP keypair (static/js/dpop.js), start the
authorization-code + PKCE flow, exchange the code with a DPoP proof, call
userinfo with proof + ath, silently refresh, and revoke on logout. The E2E
tests drive it with httpx playing the browser.
"""

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from helpers import DpopClient
from hyproxy.core.crypto import new_token, sha256_b64url

REDIRECT_URI = "https://rp.example/callback"
CLIENT_ID = "e2e-rp"


@dataclass
class RpSession:
    """What the RP frontend holds in browser storage for one user session."""

    verifier: str
    state: str
    nonce: str
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class RpSimulator:
    def __init__(self, idp: httpx.AsyncClient, issuer: str) -> None:
        self.idp = idp
        self.issuer = issuer.rstrip("/")
        self.dpop = DpopClient()  # the browser's WebCrypto keypair

    def start_login(self) -> tuple[str, RpSession]:
        """Builds the authorize URL the RP would redirect the browser to."""
        session = RpSession(verifier=new_token(48), state=new_token(24), nonce=new_token(24))
        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile email",
            "state": session.state,
            "nonce": session.nonce,
            "code_challenge": sha256_b64url(session.verifier),
            "code_challenge_method": "S256",
        }
        return f"/oidc/authorize?{urlencode(params)}", session

    def parse_callback(self, location: str, session: RpSession) -> str:
        """Validates state on the callback redirect and extracts the code."""
        query = parse_qs(urlsplit(location).query)
        assert query.get("state") == [session.state], "state mismatch (CSRF?)"
        assert "code" in query, f"no code in callback: {query}"
        return query["code"][0]

    async def exchange_code(self, code: str, session: RpSession) -> httpx.Response:
        resp = await self.idp.post(
            "/oidc/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "code_verifier": session.verifier,
            },
            headers={"DPoP": self.dpop.proof("POST", f"{self.issuer}/oidc/token")},
        )
        if resp.status_code == 200:
            body = resp.json()
            session.access_token = body["access_token"]
            session.refresh_token = body["refresh_token"]
            session.id_token = body["id_token"]
        return resp

    async def userinfo(self, session: RpSession) -> httpx.Response:
        return await self.idp.get(
            "/oidc/userinfo",
            headers={
                "Authorization": f"DPoP {session.access_token}",
                "DPoP": self.dpop.proof(
                    "GET", f"{self.issuer}/oidc/userinfo", access_token=session.access_token
                ),
            },
        )

    async def refresh(self, session: RpSession) -> httpx.Response:
        resp = await self.idp.post(
            "/oidc/token",
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": session.refresh_token,
            },
            headers={"DPoP": self.dpop.proof("POST", f"{self.issuer}/oidc/token")},
        )
        if resp.status_code == 200:
            body = resp.json()
            session.access_token = body["access_token"]
            session.refresh_token = body["refresh_token"]
        return resp

    async def logout(self, session: RpSession) -> httpx.Response:
        return await self.idp.post(
            "/oidc/revoke",
            data={"token": session.refresh_token},
            headers={"DPoP": self.dpop.proof("POST", f"{self.issuer}/oidc/revoke")},
        )

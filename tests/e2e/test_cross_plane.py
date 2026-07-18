"""Cross-plane end-to-end: the REAL compiled Go data plane in front of live
uvicorn IdP + authz services and a dummy backend.

A hand-rolled browser (managing cookies per host, following redirects, routing
each hop to the right server) logs in through the IdP, establishes a gateway
session, and reaches the backend with injected identity headers. Also covers
the deny path and immediate revocation.

Skipped automatically unless a test database and the Go toolchain are present.
"""

import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Awaitable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pyotp
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = pytest.mark.e2e

SERVER_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = SERVER_DIR.parent
DATAPLANE_DIR = REPO_DIR / "dataplane"
CERT = SERVER_DIR / ".dev" / "certs" / "idp.localhost.pem"
KEY = SERVER_DIR / ".dev" / "certs" / "idp.localhost-key.pem"

APP_HOST = "photos.home.test"
AUTH_HOST = "auth.home.test"
PW = "pw-cross-plane"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _async_db_url() -> str | None:
    url = os.environ.get("HYPROXY_TEST_DB_URL")
    if not url:
        sock = SERVER_DIR / ".dev" / "pgsocket"
        if sock.exists():
            url = f"postgresql+asyncpg://postgres@/hyproxy_test?host={sock}"
    return url


def _run_async[T](coro: Awaitable[T]) -> T:
    return asyncio.new_event_loop().run_until_complete(coro)  # type: ignore[arg-type]


def _wait(url: str, *, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            r = httpx.get(url, verify=False, timeout=2.0)  # noqa: S501
            if r.status_code < 500:
                return
        except Exception as exc:
            last = repr(exc)
        time.sleep(0.2)
    raise RuntimeError(f"service at {url} never became ready: {last}")


def _wait_tcp(port: int, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(1.0)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.2)
    raise RuntimeError(f"port {port} never opened")


class Browser:
    """Minimal cross-host browser: per-host cookie jars, manual redirects."""

    def __init__(self, idp_port: int, proxy_port: int) -> None:
        self.idp_port = idp_port
        self.proxy_port = proxy_port
        self.client = httpx.Client(verify=False, timeout=10.0)  # noqa: S501 (dev cert)
        self.cookies: dict[str, dict[str, str]] = {"idp": {}, "app": {}}

    def close(self) -> None:
        self.client.close()

    def _route(self, netloc: str) -> tuple[int, str, str]:
        host = netloc.split(":", 1)[0]
        if host == "127.0.0.1":
            return self.idp_port, netloc, "idp"
        if host in (APP_HOST, AUTH_HOST):
            return self.proxy_port, host, "app"
        raise AssertionError(f"unexpected host {netloc}")

    def request(
        self, method: str, url: str, *, data: dict[str, str] | None = None
    ) -> httpx.Response:
        parts = urlsplit(url)
        port, header_host, scope = self._route(parts.netloc)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        headers = {"Host": header_host}
        jar = self.cookies[scope]
        if jar:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        resp = self.client.request(
            method,
            f"https://127.0.0.1:{port}{path}",
            data=data,
            headers=headers,
            follow_redirects=False,
        )
        self._absorb(scope, resp)
        return resp

    def _absorb(self, scope: str, resp: httpx.Response) -> None:
        jar = self.cookies[scope]
        for raw in resp.headers.get_list("set-cookie"):
            first = raw.split(";", 1)[0]
            if "=" not in first:
                continue
            k, v = first.split("=", 1)
            low = raw.lower()
            if v == "" or "max-age=0" in low or "01 jan 1970" in low:
                jar.pop(k, None)
            else:
                jar[k] = v

    def follow(
        self, method: str, url: str, *, data: dict[str, str] | None = None, max_hops: int = 12
    ) -> httpx.Response:
        resp = self.request(method, url, data=data)
        hops = 0
        while resp.is_redirect and hops < max_hops:
            location = self._absolute(url, resp.headers["location"])
            url = location
            resp = self.request("GET", url)
            hops += 1
        return resp

    @staticmethod
    def _absolute(current: str, location: str) -> str:
        if location.startswith("/"):
            base = urlsplit(current)
            return f"{base.scheme}://{base.netloc}{location}"
        return location


def extract_fields(html: str) -> dict[str, str]:
    import re

    return dict(re.findall(r'name="(\w+)" value="([^"]*)"', html))


async def _seed(async_db_url: str, backend_port: int) -> dict[str, str]:
    from hyproxy.core import keys as key_service
    from hyproxy.core.secrets import get_secrets_backend
    from hyproxy.db import models as m
    from hyproxy.db.models import Base
    from hyproxy.security.passwords import hash_password
    from hyproxy.security.totp import generate_secret, store_pending_secret

    engine = create_async_engine(async_db_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    backend = get_secrets_backend()
    out: dict[str, str] = {}
    async with maker() as s, s.begin():
        await key_service.bootstrap_if_empty(s, backend, datetime.now(UTC))
        s.add(
            m.OAuthClient(
                client_id="gateway",
                client_name="Gateway",
                redirect_uris=[f"https://{AUTH_HOST}/gateway/callback"],
            )
        )
        email = f"{uuid.uuid4()}@example.com"
        user = m.User(
            external_id=f"user-{uuid.uuid4()}",
            email=email,
            display_name="Cross Plane",
            status="active",
            auth_tier="standard",
            password_hash=hash_password(PW),
        )
        s.add(user)
        await s.flush()
        secret = generate_secret()
        row = await store_pending_secret(s, backend, user.id, secret)
        row.confirmed_at = datetime.now(UTC)
        resource = m.Resource(
            name="photos",
            protocol="http",
            public_host=APP_HOST,
            host="127.0.0.1",
            ports=[backend_port],
        )
        s.add(resource)
        await s.flush()
        role = m.Role(name="photo-users")
        s.add(role)
        await s.flush()
        s.add(m.UserRole(user_id=user.id, role_id=role.id))
        s.add(
            m.Policy(
                role_id=role.id,
                resource_id=resource.id,
                action="allow",
                allowed_paths=["/photos"],
                conditions_json={},
            )
        )
        out = {
            "email": email,
            "totp_secret": secret,
            "user_external_id": user.external_id,
        }
    await engine.dispose()
    return out


async def _revoke_sessions(async_db_url: str, email: str) -> None:
    engine = create_async_engine(async_db_url)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE sessions SET revoked_at = now() "
                "WHERE user_id = (SELECT id FROM users WHERE email = :e)"
            ),
            {"e": email},
        )
    await engine.dispose()


def _build_dataplane() -> Path:
    out = DATAPLANE_DIR / "bin" / "dataplane-e2e"
    subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/dataplane"],
        cwd=str(DATAPLANE_DIR),
        check=True,
    )
    return out


@pytest.fixture
def cross_plane() -> Iterator[dict[str, object]]:
    async_db_url = _async_db_url()
    if async_db_url is None:
        pytest.skip("no test database available")
    if shutil.which("go") is None:
        pytest.skip("go toolchain not available")
    if not CERT.exists():
        pytest.skip("dev TLS cert missing (run make gen-certs)")

    idp_port, authz_port, backend_port, proxy_port = (
        _free_port(),
        _free_port(),
        _free_port(),
        _free_port(),
    )
    issuer = f"https://127.0.0.1:{idp_port}"
    seed = _run_async(_seed(async_db_url, backend_port))
    binary = _build_dataplane()

    env = os.environ.copy()
    env.update(
        {
            "HYPROXY_DB_URL": async_db_url,
            "HYPROXY_MASTER_KEY_FILE": str(SERVER_DIR / ".dev" / "master.keys"),
            "HYPROXY_ISSUER": issuer,
            "HYPROXY_AUTH_HOST": AUTH_HOST,
            "HYPROXY_EXTERNAL_SCHEME": "https",
            "HYPROXY_GATEWAY_COOKIE_DOMAIN": ".home.test",
            "HYPROXY_IDP_INTERNAL_URL": issuer,
            "HYPROXY_IDP_VERIFY_TLS": "false",
        }
    )
    backend_env = {**env, "PYTHONPATH": str(SERVER_DIR / "tests" / "e2e")}

    procs: list[subprocess.Popen[bytes]] = []

    def spawn(args: list[str], proc_env: dict[str, str]) -> None:
        procs.append(subprocess.Popen(args, cwd=str(SERVER_DIR), env=proc_env))

    uv = [sys.executable, "-m", "uvicorn"]
    spawn(
        uv
        + [
            "hyproxy.idp.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(idp_port),
            "--ssl-keyfile",
            str(KEY),
            "--ssl-certfile",
            str(CERT),
        ],
        env,
    )
    spawn(uv + ["hyproxy.authz.app:app", "--host", "127.0.0.1", "--port", str(authz_port)], env)
    spawn(uv + ["backend_app:app", "--host", "127.0.0.1", "--port", str(backend_port)], backend_env)

    dp_config = {
        "listen": f"127.0.0.1:{proxy_port}",
        "tls_cert": str(CERT),
        "tls_key": str(KEY),
        "authz_url": f"http://127.0.0.1:{authz_port}",
        "auth_host": AUTH_HOST,
        "auth_backend": f"http://127.0.0.1:{authz_port}",
        "gateway_cookie_name": "__Secure-gw",
        "routes": {APP_HOST: {"backend": f"http://127.0.0.1:{backend_port}"}},
    }
    cfg_path = SERVER_DIR / ".dev" / "dp-e2e-config.json"
    cfg_path.write_text(json.dumps(dp_config))
    procs.append(subprocess.Popen([str(binary), "-config", str(cfg_path)], cwd=str(DATAPLANE_DIR)))

    try:
        _wait(f"{issuer}/healthz")
        _wait(f"http://127.0.0.1:{authz_port}/healthz")
        _wait(f"http://127.0.0.1:{backend_port}/healthz")
        _wait_tcp(proxy_port)
        yield {
            "issuer": issuer,
            "seed": seed,
            "db": async_db_url,
            "idp_port": idp_port,
            "proxy_port": proxy_port,
        }
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


def _login(browser: Browser, issuer: str, seed: dict[str, str], target: str) -> httpx.Response:
    resp = browser.request("GET", target)
    assert resp.status_code == 302, resp.text  # auth_required redirect
    resp = browser.follow("GET", resp.headers["location"])  # start -> authorize -> login page
    assert "Sign in" in resp.text, resp.text[:200]

    fields = extract_fields(resp.text)
    resp = browser.request(
        "POST", f"{issuer}/auth/login", data={**fields, "email": seed["email"], "password": PW}
    )
    assert resp.status_code == 303, resp.text
    page = browser.request("GET", browser._absolute(f"{issuer}/", resp.headers["location"]))
    fields = extract_fields(page.text)
    code = pyotp.TOTP(seed["totp_secret"]).now()
    resp = browser.request("POST", f"{issuer}/auth/totp", data={**fields, "code": code})
    assert resp.status_code == 303, resp.text
    return browser.follow("GET", browser._absolute(f"{issuer}/", resp.headers["location"]))


def test_cross_plane_login_and_proxy(cross_plane: dict[str, object]) -> None:
    browser = Browser(int(cross_plane["idp_port"]), int(cross_plane["proxy_port"]))  # type: ignore[arg-type]
    issuer: str = cross_plane["issuer"]  # type: ignore[assignment]
    seed: dict[str, str] = cross_plane["seed"]  # type: ignore[assignment]
    try:
        final = _login(browser, issuer, seed, f"https://{APP_HOST}/photos")
        assert final.status_code == 200, final.text
        body = final.json()
        assert body["path"] == "/photos"
        assert body["user"] == seed["email"]
        assert body["user_id"] == seed["user_external_id"]
        assert body["roles"] == "photo-users"
        assert body["saw_gateway_cookie"] is False  # data plane stripped it

        denied = browser.request("GET", f"https://{APP_HOST}/admin")
        assert denied.status_code == 403

        # Spoofed identity header must be overwritten, never trusted.
        spoof = browser.client.get(
            f"https://127.0.0.1:{browser.proxy_port}/photos",
            headers={
                "Host": APP_HOST,
                "X-Forwarded-User": "attacker@evil.test",
                "Cookie": "; ".join(f"{k}={v}" for k, v in browser.cookies["app"].items()),
            },
            follow_redirects=False,
        )
        assert spoof.status_code == 200 and spoof.json()["user"] == seed["email"]
    finally:
        browser.close()


def test_cross_plane_revocation_kills_access(cross_plane: dict[str, object]) -> None:
    browser = Browser(int(cross_plane["idp_port"]), int(cross_plane["proxy_port"]))  # type: ignore[arg-type]
    issuer: str = cross_plane["issuer"]  # type: ignore[assignment]
    seed: dict[str, str] = cross_plane["seed"]  # type: ignore[assignment]
    db: str = cross_plane["db"]  # type: ignore[assignment]
    try:
        assert _login(browser, issuer, seed, f"https://{APP_HOST}/photos").status_code == 200
        _run_async(_revoke_sessions(db, seed["email"]))
        after = browser.request("GET", f"https://{APP_HOST}/photos")
        assert after.status_code != 200
        assert after.status_code in (302, 401, 403)
    finally:
        browser.close()

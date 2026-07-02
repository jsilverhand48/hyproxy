"""Dummy protected backend for the cross-plane E2E: echoes back the identity
headers the data plane injected, so the test can assert on them."""

from fastapi import FastAPI, Request

app = FastAPI()


@app.get("/{path:path}")
async def echo(path: str, request: Request) -> dict[str, object]:
    return {
        "path": "/" + path,
        "user": request.headers.get("X-Forwarded-User"),
        "user_id": request.headers.get("X-Auth-User-Id"),
        "roles": request.headers.get("X-Auth-Roles"),
        "saw_gateway_cookie": "__Secure-gw" in request.headers.get("cookie", ""),
    }

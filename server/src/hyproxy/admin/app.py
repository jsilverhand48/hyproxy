from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from hyproxy.admin.routes.policies import router as policies_router
from hyproxy.admin.routes.resources import router as resources_router
from hyproxy.admin.routes.roles import router as roles_router
from hyproxy.admin.routes.user_roles import router as user_roles_router
from hyproxy.admin.routes.users import router as users_router
from hyproxy.admin.routes.viewers import router as viewers_router
from hyproxy.config import SERVER_DIR, get_settings


def _idp_origin() -> str:
    parts = urlsplit(get_settings().issuer)
    return f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""


def _csp() -> str:
    # The SPA fetches its own /api (self) and the IdP token endpoint (connect to
    # the IdP origin). Scripts/styles are self-hosted, hashed assets: no inline,
    # no eval. Navigations to the IdP (authorize / step-up) are top-level, not
    # governed by connect-src.
    connect = "'self'"
    origin = _idp_origin()
    if origin:
        connect += f" {origin}"
    return (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        f"connect-src {connect}; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'"
    )


def _dist_dir() -> Path:
    configured = get_settings().admin_ui_dist
    return Path(configured) if configured else SERVER_DIR.parent / "ui" / "dist"


def create_app() -> FastAPI:
    """Management-plane API + admin SPA. Never internet-facing: bind loopback,
    reach over LAN/WireGuard only (docs/admin-access.md)."""
    app = FastAPI(title="hyproxy-admin", docs_url=None, redoc_url=None, openapi_url=None)

    csp = _csp()

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    app.include_router(users_router)
    app.include_router(roles_router)
    app.include_router(user_roles_router)
    app.include_router(resources_router)
    app.include_router(policies_router)
    app.include_router(viewers_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "admin"}

    _mount_spa(app)
    return app


def _mount_spa(app: FastAPI) -> None:
    """Serve the built SPA when present: hashed assets under /assets and an
    index.html fallback for every non-API route (client-side routing). Absent a
    build, the API runs alone."""
    dist = _dist_dir()
    index = dist / "index.html"
    if not index.is_file():
        return

    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str) -> Response:
        # API and health paths are handled above; never shadow them with HTML.
        if full_path.startswith("api/") or full_path == "healthz":
            raise HTTPException(status_code=404, detail="not found")
        return FileResponse(index)


app = create_app()

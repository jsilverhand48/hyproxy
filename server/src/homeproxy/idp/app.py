from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles

from hyproxy.idp.oidc.authorize import router as authorize_router
from hyproxy.idp.oidc.discovery import router as discovery_router
from hyproxy.idp.oidc.revoke import router as revoke_router
from hyproxy.idp.oidc.token import router as token_router
from hyproxy.idp.oidc.userinfo import router as userinfo_router
from hyproxy.idp.web.routes import router as web_router
from hyproxy.idp.web.webauthn_routes import router as webauthn_router

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def create_app() -> FastAPI:
    app = FastAPI(title="hyproxy-idp", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
        if request.url.path.startswith(("/auth", "/oidc")):
            # JWKS sets its own max-age; everything else on the auth surface is no-store.
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.include_router(discovery_router)
    app.include_router(authorize_router)
    app.include_router(token_router)
    app.include_router(userinfo_router)
    app.include_router(revoke_router)
    app.include_router(web_router)
    app.include_router(webauthn_router)
    app.mount(
        "/static", StaticFiles(directory=Path(__file__).parent / "web" / "static"), name="static"
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "idp"}

    return app


app = create_app()

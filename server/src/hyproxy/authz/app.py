"""The authz service: policy decision point + gateway RP endpoints.

Internal-only service (loopback / data-plane network). The data plane calls
/authz/check per request and routes browser traffic for the auth host's
/gateway/* paths here. Never expose /authz/check to clients.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from hyproxy.authz.check import router as check_router
from hyproxy.authz.gateway import router as gateway_router
from hyproxy.authz.guac import router as guac_router
from hyproxy.authz.routes import router as routes_router
from hyproxy.config import get_settings
from hyproxy.logs import setup_logging


def create_app(idp_http: httpx.AsyncClient | None = None) -> FastAPI:
    setup_logging("authz")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings = get_settings()
        base = (settings.idp_internal_url or settings.issuer).rstrip("/")
        app.state.idp_http = idp_http or httpx.AsyncClient(
            base_url=base, verify=settings.idp_verify_tls
        )
        yield
        await app.state.idp_http.aclose()

    app = FastAPI(
        title="hyproxy-authz",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.include_router(check_router)
    app.include_router(routes_router)
    app.include_router(gateway_router)
    app.include_router(guac_router)

    # The guac connect view runs on the SPA origins and must POST the
    # cookie-authed /guac/token cross-origin (the data plane only exposes
    # /gateway/* and /guac/token from this app to browsers, so this is
    # effectively scoped to those). Credentials are required: the endpoint
    # authenticates via the gateway session cookie.
    settings = get_settings()
    spa_origins = [o for o in (settings.admin_ui_origin, settings.portal_origin) if o]
    if spa_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=spa_origins,
            allow_methods=["POST"],
            allow_headers=["content-type"],
            allow_credentials=True,
            max_age=600,
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "authz"}

    return app


app = create_app()

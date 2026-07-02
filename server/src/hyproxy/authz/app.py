"""The authz service: policy decision point + gateway RP endpoints.

Internal-only service (loopback / data-plane network). The data plane calls
/authz/check per request and routes browser traffic for the auth host's
/gateway/* paths here. Never expose /authz/check to clients.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from hyproxy.authz.check import router as check_router
from hyproxy.authz.gateway import router as gateway_router
from hyproxy.config import get_settings


def create_app(idp_http: httpx.AsyncClient | None = None) -> FastAPI:
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
    app.include_router(gateway_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "authz"}

    return app


app = create_app()

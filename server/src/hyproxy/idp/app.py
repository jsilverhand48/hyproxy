from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware

from hyproxy.config import get_settings
from hyproxy.idp.oidc.authorize import router as authorize_router
from hyproxy.idp.oidc.discovery import router as discovery_router
from hyproxy.idp.oidc.revoke import router as revoke_router
from hyproxy.idp.oidc.token import router as token_router
from hyproxy.idp.oidc.userinfo import router as userinfo_router
from hyproxy.idp.web.routes import router as web_router
from hyproxy.idp.web.webauthn_routes import router as webauthn_router
from hyproxy.logs import setup_logging


def _csp() -> str:
    """Build the auth-surface CSP.

    The post-login flow is a form submission (password / second-factor pages)
    whose redirect chain deliberately leaves the IdP origin:
    /auth/* -> /oidc/authorize -> the auth host's /gateway/callback -> the
    resource the user originally requested. Browsers enforce form-action across
    the *entire* redirect chain of a form navigation, so form-action 'self'
    silently cancels the hop to the auth host: the user's second factor is
    accepted (the session is created server-side) but the browser never moves,
    and only a manual address-bar navigation - which form-action does not gate -
    reaches the resource. Permit the deployment's own parent domain (the same
    value that scopes the cross-subdomain gateway cookie) so the auth host and
    every resource subdomain are reachable from these forms; 'self' alone breaks
    the flow. When no cross-subdomain domain is configured the flow never leaves
    'self', so nothing is widened.
    """
    form_action = "'self'"
    domain = get_settings().gateway_cookie_domain
    if domain:
        form_action += f" https://*.{domain} https://{domain}"
    return (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        f"connect-src 'self'; form-action {form_action}; "
        "frame-ancestors 'none'; base-uri 'none'"
    )


def create_app() -> FastAPI:
    setup_logging("idp")
    app = FastAPI(title="hyproxy-idp", docs_url=None, redoc_url=None, openapi_url=None)
    csp = _csp()

    # The SPA (served on the management-plane origin and, for the standard-user
    # portal, on portal_origin) must reach the cross-origin token/userinfo
    # endpoints. Allow exactly those configured origins, the two request
    # headers the DPoP flow needs, and no credentials (the flow is bearer/DPoP,
    # never cookie). No configured origins leaves CORS off.
    settings = get_settings()
    spa_origins = [o for o in (settings.admin_ui_origin, settings.portal_origin) if o]
    if spa_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=spa_origins,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["authorization", "dpop", "content-type"],
            allow_credentials=False,
            max_age=600,
        )

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", csp)
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

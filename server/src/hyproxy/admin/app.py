from fastapi import FastAPI

from hyproxy.admin.routes.policies import router as policies_router
from hyproxy.admin.routes.resources import router as resources_router
from hyproxy.admin.routes.roles import router as roles_router
from hyproxy.admin.routes.user_roles import router as user_roles_router
from hyproxy.admin.routes.users import router as users_router


def create_app() -> FastAPI:
    """Management-plane API. Never internet-facing: bind loopback, reach over
    LAN/WireGuard only (docs/admin-access.md)."""
    app = FastAPI(title="hyproxy-admin", docs_url=None, redoc_url=None, openapi_url=None)
    app.include_router(users_router)
    app.include_router(roles_router)
    app.include_router(user_roles_router)
    app.include_router(resources_router)
    app.include_router(policies_router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "service": "admin"}

    return app


app = create_app()

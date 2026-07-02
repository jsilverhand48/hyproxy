from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from hyproxy.config import get_settings
from hyproxy.core.keys import get_verification_jwks
from hyproxy.db.engine import get_db

router = APIRouter()


@router.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict[str, Any]:
    issuer = get_settings().issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oidc/authorize",
        "token_endpoint": f"{issuer}/oidc/token",
        "userinfo_endpoint": f"{issuer}/oidc/userinfo",
        "revocation_endpoint": f"{issuer}/oidc/revoke",
        "jwks_uri": f"{issuer}/oidc/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "profile", "email"],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "claims_supported": ["sub", "email", "name", "auth_tier", "auth_time", "amr", "acr"],
    }


@router.get("/oidc/jwks")
async def jwks(db: Annotated[AsyncSession, Depends(get_db)]) -> JSONResponse:
    keys = await get_verification_jwks(db)
    max_age = get_settings().jwks_cache_max_age
    return JSONResponse(keys, headers={"Cache-Control": f"max-age={max_age}"})

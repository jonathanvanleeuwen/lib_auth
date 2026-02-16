from fastapi import APIRouter, Depends

from lib_auth.auth.oauth_auth import create_access_token
from lib_auth.models.oauth import (
    AuthorizationRequest,
    TokenRequest,
    TokenResponse,
)
from lib_auth.settings import Settings, get_settings
from lib_auth.utils.auth_utils import get_user_roles
from lib_auth.workers.oauth_service import (
    build_authorization_url,
    exchange_code_for_provider_token,
    extract_user_email,
    get_user_info_from_provider,
)

_depends_settings = Depends(get_settings)

oauth_router = APIRouter(tags=["oauth"], prefix="/auth/oauth")


@oauth_router.get("/provider", status_code=200)
def get_provider_info(settings: Settings = _depends_settings) -> dict[str, str]:
    return {"provider": settings.oauth_provider}


@oauth_router.post("/authorize", status_code=200)
def get_authorization_url(
    request: AuthorizationRequest,
    settings: Settings = _depends_settings,
) -> dict[str, str]:
    auth_url = build_authorization_url(
        provider=settings.oauth_provider,
        client_id=settings.oauth_client_id,
        redirect_uri=request.redirect_uri,
    )
    return {"authorization_url": auth_url}


@oauth_router.post("/token", status_code=200)
async def exchange_code_for_token(
    request: TokenRequest,
    settings: Settings = _depends_settings,
) -> TokenResponse:
    provider_access_token = await exchange_code_for_provider_token(
        provider=settings.oauth_provider,
        code=request.code,
        client_id=settings.oauth_client_id,
        client_secret=settings.oauth_client_secret,
        redirect_uri=request.redirect_uri,
    )
    user_info = await get_user_info_from_provider(
        provider=settings.oauth_provider,
        provider_access_token=provider_access_token,
    )
    user_email = extract_user_email(user_info)
    user_roles = get_user_roles(user_email)
    access_token = create_access_token(
        data={"sub": user_email, "provider": settings.oauth_provider},
        roles=user_roles,
    )
    return TokenResponse(access_token=access_token)

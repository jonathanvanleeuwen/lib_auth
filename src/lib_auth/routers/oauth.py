from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import APIRouter

from lib_auth.auth.oauth_auth import create_access_token
from lib_auth.auth.oauth_providers import register_oauth_provider
from lib_auth.models.oauth import AuthorizationRequest, TokenRequest, TokenResponse
from lib_auth.utils.auth_utils import resolve_user_roles
from lib_auth.workers.oauth_service import (
    build_authorization_url,
    exchange_code_for_provider_token,
    extract_user_email,
    get_user_info_from_provider,
)

logger = logging.getLogger(__name__)


def create_oauth_router(
    oauth_provider: str,
    oauth_client_id: str,
    oauth_client_secret: str,
    oauth_secret_key: str,
    oauth_access_token_expire_minutes: int,
    user_role_resolver: Callable[[str], list[str] | Awaitable[list[str]]] | None = None,
    oauth_provider_config: dict[str, str] | None = None,
) -> APIRouter:
    """Create an OAuth router for FastAPI.

    Args:
        oauth_provider: Provider name (e.g., "github", "google", "microsoft")
        oauth_client_id: OAuth client ID from provider
        oauth_client_secret: OAuth client secret from provider
        oauth_secret_key: Secret key for signing JWT tokens
        oauth_access_token_expire_minutes: Token expiration time in minutes
        user_role_resolver: Optional function to resolve user roles from email
        oauth_provider_config: Optional custom provider config dict with keys:
            - authorization_url: OAuth authorization endpoint
            - token_url: OAuth token exchange endpoint
            - userinfo_url: User info endpoint
            - scope: OAuth scopes (space-separated)

    Example with custom provider:
        create_oauth_router(
            oauth_provider="custom",
            oauth_provider_config={
                "authorization_url": "https://custom.com/oauth/authorize",
                "token_url": "https://custom.com/oauth/token",
                "userinfo_url": "https://custom.com/api/user",
                "scope": "email profile",
            },
            ...
        )
    """
    if oauth_provider_config:
        register_oauth_provider(
            name=oauth_provider,
            authorization_url=oauth_provider_config["authorization_url"],
            token_url=oauth_provider_config["token_url"],
            userinfo_url=oauth_provider_config["userinfo_url"],
            scope=oauth_provider_config["scope"],
        )

    router = APIRouter(tags=["oauth"], prefix="/auth/oauth")

    @router.get("/provider", status_code=200)
    def get_provider_info() -> dict[str, str]:
        return {"provider": oauth_provider}

    @router.post("/authorize", status_code=200)
    def get_authorization_url(request: AuthorizationRequest) -> dict[str, str]:
        auth_url = build_authorization_url(
            provider=oauth_provider,
            client_id=oauth_client_id,
            redirect_uri=request.redirect_uri,
        )
        return {"authorization_url": auth_url}

    @router.post("/token", status_code=200)
    async def exchange_code_for_token(request: TokenRequest) -> TokenResponse:
        provider_access_token = await exchange_code_for_provider_token(
            provider=oauth_provider,
            code=request.code,
            client_id=oauth_client_id,
            client_secret=oauth_client_secret,
            redirect_uri=request.redirect_uri,
        )
        user_info = await get_user_info_from_provider(
            provider=oauth_provider,
            provider_access_token=provider_access_token,
        )
        user_email = extract_user_email(user_info)
        user_roles = await resolve_user_roles(user_role_resolver, user_email)
        access_token = create_access_token(
            data={"sub": user_email, "provider": oauth_provider},
            roles=user_roles,
            secret_key=oauth_secret_key,
            expire_minutes=oauth_access_token_expire_minutes,
        )
        logger.info(
            "OAuth login successful: provider=%s user=%s roles=%s",
            oauth_provider,
            user_email,
            user_roles,
        )
        return TokenResponse(access_token=access_token)

    return router

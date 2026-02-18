"""Azure Entra ID service authentication provider."""

import logging
import time
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, status

from lib_auth.service_auth.base_provider import ServiceAuthProvider
from lib_auth.service_auth.jwt_utils import (
    extract_public_key_from_jwks,
    fetch_jwks,
    handle_jwt_exceptions,
)
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceTokenPayload

logger = logging.getLogger(__name__)


class AzureServiceAuthProvider(ServiceAuthProvider):
    """
    Azure Entra ID (formerly Azure AD) service authentication.

    Uses client credentials flow with client ID and secret to obtain
    access tokens for service-to-service authentication.
    """

    def __init__(self, config: ServiceAuthConfig):
        super().__init__(config)
        if not config.tenant_id:
            msg = "Azure provider requires tenant_id"
            raise ValueError(msg)
        if not config.client_id:
            msg = "Azure provider requires client_id"
            raise ValueError(msg)
        if not config.client_secret:
            msg = "Azure provider requires client_secret"
            raise ValueError(msg)

        self.tenant_id = config.tenant_id
        self.client_id = config.client_id
        self.client_secret = config.client_secret
        self._token_cache: dict[str, tuple[str, float]] = {}
        self._jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}

    async def get_token(self, target_audience: str, service_name: str) -> str:
        """
        Get an access token from Azure Entra ID for the target service.

        Args:
            target_audience: The Azure application ID URI of the target service
            service_name: Name of the requesting service (for logging)

        Returns:
            JWT access token
        """
        cache_key = f"{target_audience}:{service_name}"
        if cache_key in self._token_cache:
            token, expires_at = self._token_cache[cache_key]
            if time.time() < expires_at - 60:
                logger.debug(
                    "Using cached Azure token for audience=%s", target_audience
                )
                return token

        token_endpoint = (
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        )

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": f"{target_audience}/.default",
            "grant_type": "client_credentials",
        }

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(token_endpoint, data=data, timeout=10.0)
                response.raise_for_status()
            except httpx.HTTPError as e:
                logger.exception("Failed to get Azure token: %s", e)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Failed to obtain Azure access token",
                ) from e

        token_data = response.json()
        access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)

        expires_at = time.time() + expires_in
        self._token_cache[cache_key] = (access_token, expires_at)

        logger.info(
            "Obtained Azure token for audience=%s service=%s",
            target_audience,
            service_name,
        )
        return access_token

    async def _get_jwks(self) -> dict[str, Any]:
        """Get and cache the Azure JWKS (JSON Web Key Set) for token verification."""
        jwks_uri = (
            f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
        )
        return await fetch_jwks(
            jwks_url=jwks_uri,
            cache=self._jwks_cache,
            error_detail="Failed to retrieve Azure public keys",
        )

    async def verify_token(self, token: str) -> ServiceTokenPayload:
        """
        Verify an Azure Entra ID access token.

        Args:
            token: The JWT token to verify

        Returns:
            Verified token payload

        Raises:
            HTTPException: If token is invalid, expired, or audience mismatch
        """
        try:
            jwks = await self._get_jwks()
            public_key = extract_public_key_from_jwks(token, jwks)

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.config.allowed_audiences or self.client_id,
                options={"verify_exp": True},
            )

            return ServiceTokenPayload(
                sub=payload.get("sub", payload.get("oid", "unknown")),
                aud=payload["aud"],
                iss=payload["iss"],
                exp=payload["exp"],
                iat=payload["iat"],
                service_name=payload.get(
                    "app_displayname", payload.get("azp", "unknown")
                ),
                roles=payload.get("roles", []),
                metadata={"tid": payload.get("tid"), "appid": payload.get("appid")},
            )

        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            handle_jwt_exceptions(e, "Azure")

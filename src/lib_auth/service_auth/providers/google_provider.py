"""Google Cloud Identity service authentication provider."""

import json
import logging
import time
from typing import Any

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


class GoogleServiceAuthProvider(ServiceAuthProvider):
    """
    Google Cloud Identity service authentication.

    Uses service account credentials to create and verify identity tokens
    for service-to-service authentication.
    """

    def __init__(self, config: ServiceAuthConfig):
        super().__init__(config)
        if not config.private_key:
            msg = "Google provider requires private_key (service account JSON key)"
            raise ValueError(msg)
        if not config.client_id:
            msg = "Google provider requires client_id (service account email)"
            raise ValueError(msg)

        try:
            self.service_account_data = json.loads(config.private_key)
        except json.JSONDecodeError as e:
            msg = "private_key must be valid JSON (service account key file content)"
            raise ValueError(msg) from e

        self.client_email = self.service_account_data.get(
            "client_email", config.client_id
        )
        self.private_key = self.service_account_data["private_key"]
        self.project_id = config.project_id or self.service_account_data.get(
            "project_id"
        )
        self._token_cache: dict[str, tuple[str, float]] = {}
        self._jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}

    async def get_token(self, target_audience: str, service_name: str) -> str:
        """
        Create a Google Cloud identity token for the target service.

        Args:
            target_audience: The target service URL or identifier
            service_name: Name of the requesting service (used in metadata)

        Returns:
            Signed JWT identity token
        """
        cache_key = f"{target_audience}:{service_name}"
        if cache_key in self._token_cache:
            token, expires_at = self._token_cache[cache_key]
            if time.time() < expires_at - 60:
                logger.debug(
                    "Using cached Google token for audience=%s", target_audience
                )
                return token

        now = int(time.time())
        expiry = now + 3600

        payload = {
            "iss": self.client_email,
            "sub": self.client_email,
            "aud": target_audience,
            "iat": now,
            "exp": expiry,
            "service_name": service_name,
        }

        try:
            token = jwt.encode(payload, self.private_key, algorithm="RS256")
        except Exception as e:
            logger.exception("Failed to sign Google token: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create identity token",
            ) from e

        self._token_cache[cache_key] = (token, expiry)

        logger.info(
            "Created Google identity token for audience=%s service=%s",
            target_audience,
            service_name,
        )
        return token

    async def _get_google_public_keys(self) -> dict[str, Any]:
        """Get and cache Google's public keys for token verification."""
        return await fetch_jwks(
            jwks_url="https://www.googleapis.com/oauth2/v3/certs",
            cache=self._jwks_cache,
            error_detail="Failed to retrieve Google public keys",
        )

    async def verify_token(self, token: str) -> ServiceTokenPayload:
        """
        Verify a Google Cloud identity token.

        Args:
            token: The JWT token to verify

        Returns:
            Verified token payload

        Raises:
            HTTPException: If token is invalid, expired, or audience mismatch
        """
        try:
            jwks = await self._get_google_public_keys()
            public_key = extract_public_key_from_jwks(token, jwks)

            allowed_audiences = self.config.allowed_audiences or []
            if self.client_email not in allowed_audiences:
                allowed_audiences.append(self.client_email)

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=allowed_audiences if allowed_audiences else None,
                options={"verify_exp": True, "verify_aud": bool(allowed_audiences)},
            )

            return ServiceTokenPayload(
                sub=payload.get("sub", "unknown"),
                aud=payload.get("aud", ""),
                iss=payload.get("iss", ""),
                exp=payload["exp"],
                iat=payload["iat"],
                service_name=payload.get("service_name", payload.get("sub", "unknown")),
                roles=payload.get("roles", []),
                metadata={
                    "email": payload.get("email"),
                    "email_verified": payload.get("email_verified"),
                },
            )

        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
            handle_jwt_exceptions(e, "Google")

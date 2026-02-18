"""GitHub App service authentication provider."""

import logging
import time

import jwt
from fastapi import HTTPException, status

from lib_auth.service_auth.base_provider import ServiceAuthProvider
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceTokenPayload

logger = logging.getLogger(__name__)


class GitHubServiceAuthProvider(ServiceAuthProvider):
    """
    GitHub App service authentication.

    Uses GitHub App credentials to create and verify JWT tokens for
    service-to-service authentication between GitHub App installations.

    Note: This is a custom implementation for microservices that want to
    authenticate using GitHub App patterns, not official GitHub API authentication.
    """

    def __init__(self, config: ServiceAuthConfig):
        super().__init__(config)
        if not config.app_id:
            msg = "GitHub provider requires app_id (GitHub App ID)"
            raise ValueError(msg)
        if not config.private_key:
            msg = "GitHub provider requires private_key (GitHub App private key in PEM format)"
            raise ValueError(msg)

        self.app_id = config.app_id
        self.private_key = config.private_key
        self.issuer = config.issuer or f"github-app-{self.app_id}"
        self._token_cache: dict[str, tuple[str, float]] = {}

    async def get_token(self, target_audience: str, service_name: str) -> str:
        """
        Create a JWT token for authenticating to another service.

        Args:
            target_audience: The target service identifier
            service_name: Name of the requesting service

        Returns:
            Signed JWT token
        """
        cache_key = f"{target_audience}:{service_name}"
        if cache_key in self._token_cache:
            token, expires_at = self._token_cache[cache_key]
            if time.time() < expires_at - 60:
                logger.debug(
                    "Using cached GitHub token for audience=%s", target_audience
                )
                return token

        now = int(time.time())
        expiry = now + 600

        payload = {
            "iss": self.issuer,
            "sub": service_name,
            "aud": target_audience,
            "iat": now,
            "exp": expiry,
            "service_name": service_name,
            "github_app_id": self.app_id,
        }

        try:
            token = jwt.encode(payload, self.private_key, algorithm="RS256")
        except Exception as e:
            logger.exception("Failed to sign GitHub token: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create token",
            ) from e

        self._token_cache[cache_key] = (token, expiry)

        logger.info(
            "Created GitHub App token for audience=%s service=%s",
            target_audience,
            service_name,
        )
        return token

    async def verify_token(self, token: str) -> ServiceTokenPayload:
        """
        Verify a GitHub App JWT token.

        Args:
            token: The JWT token to verify

        Returns:
            Verified token payload

        Raises:
            HTTPException: If token is invalid, expired, or audience mismatch
        """
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization

            private_key_obj = serialization.load_pem_private_key(
                self.private_key.encode(),
                password=None,
                backend=default_backend(),
            )

            public_key = private_key_obj.public_key()

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            allowed_audiences = self.config.allowed_audiences or []
            if self.issuer not in allowed_audiences:
                allowed_audiences.append(self.issuer)

            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            issuer = unverified_payload.get("iss")

            if not issuer:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing issuer",
                )

            payload = jwt.decode(
                token,
                public_pem,
                algorithms=["RS256"],
                audience=allowed_audiences if allowed_audiences else None,
                issuer=issuer,
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
                    "github_app_id": payload.get("github_app_id"),
                },
            )

        except jwt.ExpiredSignatureError as e:
            logger.warning("GitHub token expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
            ) from e
        except jwt.InvalidTokenError as e:
            logger.warning("GitHub token invalid: %s", e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            ) from e

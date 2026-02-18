"""FastAPI dependencies for service-to-service authentication."""

import logging
from collections.abc import Callable

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lib_auth.service_auth.models import ServiceAuthConfig, ServiceTokenPayload
from lib_auth.service_auth.provider_factory import get_provider

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)
_security_bearer = Security(bearer_scheme)


def create_service_auth(
    config: ServiceAuthConfig,
    allowed_services: list[str] | None = None,
    required_roles: list[str] | None = None,
) -> Callable:
    """
    Create a FastAPI dependency for service-to-service authentication.

    Args:
        config: Service authentication configuration
        allowed_services: List of allowed service names (sub claim). If None, all services allowed.
        required_roles: List of required roles. If None, no role check performed.

    Returns:
        FastAPI dependency function that verifies service tokens

    Example:
        ```python
        from fastapi import Depends, FastAPI
        from lib_auth.service_auth import create_service_auth
        from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType

        app = FastAPI()

        # Configure Azure service authentication
        service_config = ServiceAuthConfig(
            provider=ServiceAuthProviderType.AZURE,
            tenant_id="your-tenant-id",
            client_id="your-client-id",
            client_secret="your-client-secret",
            allowed_audiences=["api://your-api-id"],
        )

        @app.get(
            "/api/data",
            dependencies=[
                Depends(create_service_auth(service_config, allowed_services=["service-a"]))
            ],
        )
        async def get_data(request: Request):
            service_info = request.state.service_info
            return {"message": f"Hello {service_info.service_name}"}
        ```
    """
    provider = get_provider(config)

    async def verify_service_token(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = _security_bearer,
    ) -> ServiceTokenPayload:
        if not credentials:
            logger.warning("No authorization credentials provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = credentials.credentials

        try:
            payload = await provider.verify_token(token)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Unexpected error verifying service token: %s", e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token verification failed",
            ) from e

        if allowed_services and payload.service_name not in allowed_services:
            logger.warning(
                "Service not allowed: %s (allowed: %s)",
                payload.service_name,
                allowed_services,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Service '{payload.service_name}' not authorized",
            )

        if required_roles:
            user_roles = set(payload.roles)
            if not any(role in user_roles for role in required_roles):
                logger.warning(
                    "Missing required roles for service %s: required=%s, has=%s",
                    payload.service_name,
                    required_roles,
                    payload.roles,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Service does not have required role",
                )

        request.state.service_info = payload
        logger.info(
            "Service authenticated: service=%s audience=%s",
            payload.service_name,
            payload.aud,
        )

        return payload

    return verify_service_token

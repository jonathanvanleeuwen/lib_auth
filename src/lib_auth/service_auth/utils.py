"""Utility functions for service authentication."""

import asyncio

from lib_auth.service_auth.models import ServiceAuthConfig
from lib_auth.service_auth.provider_factory import get_provider


async def get_service_token(
    config: ServiceAuthConfig,
    target_audience: str,
    service_name: str,
) -> str:
    """
    Get a service authentication token.

    Helper function for services that need to obtain tokens to call other services.

    Args:
        config: Service authentication configuration
        target_audience: The target service identifier (audience claim)
        service_name: Name of the requesting service (subject claim)

    Returns:
        JWT token for authenticating to the target service

    Example:
        ```python
        from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
        from lib_auth.service_auth.utils import get_service_token

        # Configure provider
        config = ServiceAuthConfig(
            provider=ServiceAuthProviderType.AZURE,
            tenant_id="your-tenant-id",
            client_id="your-client-id",
            client_secret="your-client-secret",
        )

        # Get token for calling Service B
        token = await get_service_token(
            config=config,
            target_audience="api://service-b",
            service_name="service-a",
        )

        # Use token to call Service B
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://service-b.example.com/api/data",
                headers={"Authorization": f"Bearer {token}"},
            )
        ```
    """
    provider = get_provider(config)
    return await provider.get_token(target_audience, service_name)


def get_service_token_sync(
    config: ServiceAuthConfig,
    target_audience: str,
    service_name: str,
) -> str:
    """
    Synchronous wrapper for get_service_token.

    Args:
        config: Service authentication configuration
        target_audience: The target service identifier
        service_name: Name of the requesting service

    Returns:
        JWT token for authenticating to the target service
    """
    return asyncio.run(get_service_token(config, target_audience, service_name))

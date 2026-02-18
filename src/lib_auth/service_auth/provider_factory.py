"""Factory for creating service authentication providers."""

from lib_auth.service_auth.base_provider import ServiceAuthProvider
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
from lib_auth.service_auth.providers.azure_provider import AzureServiceAuthProvider
from lib_auth.service_auth.providers.github_provider import GitHubServiceAuthProvider
from lib_auth.service_auth.providers.google_provider import GoogleServiceAuthProvider


def get_provider(config: ServiceAuthConfig) -> ServiceAuthProvider:
    """
    Create a service authentication provider based on configuration.

    Args:
        config: Service authentication configuration

    Returns:
        Configured provider instance

    Raises:
        ValueError: If provider type is not supported
    """
    if config.provider == ServiceAuthProviderType.AZURE:
        return AzureServiceAuthProvider(config)
    elif config.provider == ServiceAuthProviderType.GOOGLE:
        return GoogleServiceAuthProvider(config)
    elif config.provider == ServiceAuthProviderType.GITHUB:
        return GitHubServiceAuthProvider(config)
    else:
        msg = f"Unsupported provider: {config.provider}"
        raise ValueError(msg)

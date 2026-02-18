"""Unit tests for service authentication provider factory."""

import pytest

from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
from lib_auth.service_auth.provider_factory import get_provider
from lib_auth.service_auth.providers.azure_provider import AzureServiceAuthProvider
from lib_auth.service_auth.providers.github_provider import GitHubServiceAuthProvider
from lib_auth.service_auth.providers.google_provider import GoogleServiceAuthProvider


def test_get_provider_azure():
    """Test get_provider returns AzureServiceAuthProvider for Azure config."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.AZURE,
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
    )

    provider = get_provider(config)

    assert isinstance(provider, AzureServiceAuthProvider)
    assert provider.tenant_id == "test-tenant"
    assert provider.client_id == "test-client"
    assert provider.client_secret == "test-secret"


def test_get_provider_google():
    """Test get_provider returns GoogleServiceAuthProvider for Google config."""
    service_account_key = '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\ntest\\n-----END PRIVATE KEY-----", "client_email": "test@project.iam.gserviceaccount.com"}'

    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GOOGLE,
        private_key=service_account_key,
        client_id="test@project.iam.gserviceaccount.com",
    )

    provider = get_provider(config)

    assert isinstance(provider, GoogleServiceAuthProvider)
    assert provider.client_email == "test@project.iam.gserviceaccount.com"


def test_get_provider_github():
    """Test get_provider returns GitHubServiceAuthProvider for GitHub config."""
    private_key = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GITHUB,
        app_id="123456",
        private_key=private_key,
    )

    provider = get_provider(config)

    assert isinstance(provider, GitHubServiceAuthProvider)
    assert provider.app_id == "123456"


def test_azure_provider_missing_tenant_id():
    """Test Azure provider raises ValueError when tenant_id is missing."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.AZURE,
        client_id="test-client",
        client_secret="test-secret",
    )

    with pytest.raises(ValueError, match="Azure provider requires tenant_id"):
        get_provider(config)


def test_azure_provider_missing_client_id():
    """Test Azure provider raises ValueError when client_id is missing."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.AZURE,
        tenant_id="test-tenant",
        client_secret="test-secret",
    )

    with pytest.raises(ValueError, match="Azure provider requires client_id"):
        get_provider(config)


def test_azure_provider_missing_client_secret():
    """Test Azure provider raises ValueError when client_secret is missing."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.AZURE,
        tenant_id="test-tenant",
        client_id="test-client",
    )

    with pytest.raises(ValueError, match="Azure provider requires client_secret"):
        get_provider(config)


def test_google_provider_missing_private_key():
    """Test Google provider raises ValueError when private_key is missing."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GOOGLE,
        client_id="test@project.iam.gserviceaccount.com",
    )

    with pytest.raises(ValueError, match="Google provider requires private_key"):
        get_provider(config)


def test_google_provider_invalid_json():
    """Test Google provider raises ValueError when private_key is not valid JSON."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GOOGLE,
        private_key="not-valid-json",
        client_id="test@project.iam.gserviceaccount.com",
    )

    with pytest.raises(ValueError, match="private_key must be valid JSON"):
        get_provider(config)


def test_github_provider_missing_app_id():
    """Test GitHub provider raises ValueError when app_id is missing."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GITHUB,
        private_key="-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
    )

    with pytest.raises(ValueError, match="GitHub provider requires app_id"):
        get_provider(config)


def test_github_provider_missing_private_key():
    """Test GitHub provider raises ValueError when private_key is missing."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GITHUB,
        app_id="123456",
    )

    with pytest.raises(ValueError, match="GitHub provider requires private_key"):
        get_provider(config)

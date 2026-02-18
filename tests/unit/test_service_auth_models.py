"""Unit tests for service authentication models."""

from lib_auth.service_auth.models import (
    ServiceAuthConfig,
    ServiceAuthProviderType,
    ServiceTokenPayload,
)


def test_service_auth_provider_type_enum():
    """Test ServiceAuthProviderType enum values."""
    assert ServiceAuthProviderType.AZURE == "azure"
    assert ServiceAuthProviderType.GOOGLE == "google"
    assert ServiceAuthProviderType.GITHUB == "github"


def test_service_auth_config_azure():
    """Test ServiceAuthConfig for Azure provider."""
    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.AZURE,
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
        allowed_audiences=["api://test-api"],
    )

    assert config.provider == ServiceAuthProviderType.AZURE
    assert config.tenant_id == "test-tenant"
    assert config.client_id == "test-client"
    assert config.client_secret == "test-secret"
    assert config.allowed_audiences == ["api://test-api"]


def test_service_auth_config_google():
    """Test ServiceAuthConfig for Google provider."""
    service_account_key = '{"type": "service_account", "private_key": "..."}'

    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GOOGLE,
        private_key=service_account_key,
        client_id="test@project.iam.gserviceaccount.com",
        project_id="test-project",
    )

    assert config.provider == ServiceAuthProviderType.GOOGLE
    assert config.private_key == service_account_key
    assert config.client_id == "test@project.iam.gserviceaccount.com"
    assert config.project_id == "test-project"


def test_service_auth_config_github():
    """Test ServiceAuthConfig for GitHub provider."""
    private_key = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"

    config = ServiceAuthConfig(
        provider=ServiceAuthProviderType.GITHUB,
        app_id="123456",
        private_key=private_key,
    )

    assert config.provider == ServiceAuthProviderType.GITHUB
    assert config.app_id == "123456"
    assert config.private_key == private_key


def test_service_token_payload():
    """Test ServiceTokenPayload model."""
    payload = ServiceTokenPayload(
        sub="service-a",
        aud="service-b",
        iss="https://issuer.example.com",
        exp=1234567890,
        iat=1234567800,
        service_name="service-a",
        roles=["Service.Read", "Service.Write"],
        metadata={"key": "value"},
    )

    assert payload.sub == "service-a"
    assert payload.aud == "service-b"
    assert payload.iss == "https://issuer.example.com"
    assert payload.exp == 1234567890
    assert payload.iat == 1234567800
    assert payload.service_name == "service-a"
    assert payload.roles == ["Service.Read", "Service.Write"]
    assert payload.metadata == {"key": "value"}


def test_service_token_payload_defaults():
    """Test ServiceTokenPayload with default values."""
    payload = ServiceTokenPayload(
        sub="service-a",
        aud="service-b",
        iss="issuer",
        exp=1234567890,
        iat=1234567800,
        service_name="service-a",
    )

    assert payload.roles == []
    assert payload.metadata == {}


def test_service_token_payload_list_audience():
    """Test ServiceTokenPayload with list of audiences."""
    payload = ServiceTokenPayload(
        sub="service-a",
        aud=["service-b", "service-c"],
        iss="issuer",
        exp=1234567890,
        iat=1234567800,
        service_name="service-a",
    )

    assert payload.aud == ["service-b", "service-c"]

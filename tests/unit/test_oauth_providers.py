"""Unit tests for OAuth provider configuration and registration."""

from __future__ import annotations

from lib_auth.auth.oauth_providers import OAUTH_PROVIDERS, register_oauth_provider


def test_built_in_providers_exist():
    """Test that all built-in OAuth providers are available."""
    expected_providers = [
        "github",
        "google",
        "microsoft",
        "gitlab",
        "linkedin",
        "discord",
    ]

    for provider in expected_providers:
        assert provider in OAUTH_PROVIDERS


def test_github_provider_config():
    """Test GitHub provider has required configuration."""
    github = OAUTH_PROVIDERS["github"]

    assert "authorization_url" in github
    assert "token_url" in github
    assert "userinfo_url" in github
    assert "scope" in github
    assert "github.com" in github["authorization_url"]


def test_google_provider_config():
    """Test Google provider has required configuration."""
    google = OAUTH_PROVIDERS["google"]

    assert "authorization_url" in google
    assert "token_url" in google
    assert "userinfo_url" in google
    assert "scope" in google
    assert "accounts.google.com" in google["authorization_url"]


def test_register_oauth_provider():
    """Test registering a custom OAuth provider."""
    provider_name = "test-provider-unique-1"
    register_oauth_provider(
        name=provider_name,
        authorization_url="https://test.com/authorize",
        token_url="https://test.com/token",
        userinfo_url="https://test.com/userinfo",
        scope="openid email",
    )

    assert provider_name in OAUTH_PROVIDERS
    assert (
        OAUTH_PROVIDERS[provider_name]["authorization_url"]
        == "https://test.com/authorize"
    )
    assert OAUTH_PROVIDERS[provider_name]["token_url"] == "https://test.com/token"
    assert OAUTH_PROVIDERS[provider_name]["userinfo_url"] == "https://test.com/userinfo"
    assert OAUTH_PROVIDERS[provider_name]["scope"] == "openid email"


def test_register_oauth_provider_overwrites_existing():
    """Test that registering a provider with existing name overwrites it."""
    provider_name = "test-overwrite"

    # Register first time
    register_oauth_provider(
        name=provider_name,
        authorization_url="https://old.com/authorize",
        token_url="https://old.com/token",
        userinfo_url="https://old.com/userinfo",
        scope="old-scope",
    )

    # Register again with new values
    register_oauth_provider(
        name=provider_name,
        authorization_url="https://new.com/authorize",
        token_url="https://new.com/token",
        userinfo_url="https://new.com/userinfo",
        scope="new-scope",
    )

    assert (
        OAUTH_PROVIDERS[provider_name]["authorization_url"]
        == "https://new.com/authorize"
    )
    assert OAUTH_PROVIDERS[provider_name]["scope"] == "new-scope"


def test_all_providers_have_required_fields():
    """Test that all providers have the required configuration fields."""
    required_fields = ["authorization_url", "token_url", "userinfo_url", "scope"]

    for provider_name, config in OAUTH_PROVIDERS.items():
        for field in required_fields:
            assert field in config, (
                f"Provider '{provider_name}' missing field '{field}'"
            )


def test_microsoft_provider_config():
    """Test Microsoft provider configuration."""
    microsoft = OAUTH_PROVIDERS["microsoft"]

    assert "login.microsoftonline.com" in microsoft["authorization_url"]
    assert "login.microsoftonline.com" in microsoft["token_url"]
    assert "graph.microsoft.com" in microsoft["userinfo_url"]


def test_gitlab_provider_config():
    """Test GitLab provider configuration."""
    gitlab = OAUTH_PROVIDERS["gitlab"]

    assert "gitlab.com" in gitlab["authorization_url"]
    assert "gitlab.com" in gitlab["token_url"]
    assert "gitlab.com" in gitlab["userinfo_url"]


def test_discord_provider_config():
    """Test Discord provider configuration."""
    discord = OAUTH_PROVIDERS["discord"]

    assert "discord.com" in discord["authorization_url"]
    assert "discord.com" in discord["token_url"]
    assert "discord.com" in discord["userinfo_url"]

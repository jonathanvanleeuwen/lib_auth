"""Integration tests for OAuth router endpoints."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from lib_auth.routers.oauth import create_oauth_router


@pytest.fixture
def oauth_app(dummy_settings):
    """Create a FastAPI app with OAuth router."""
    app = FastAPI()
    app.include_router(
        create_oauth_router(
            oauth_provider=dummy_settings.oauth_provider,
            oauth_client_id=dummy_settings.oauth_client_id,
            oauth_client_secret=dummy_settings.oauth_client_secret,
            oauth_secret_key=dummy_settings.oauth_secret_key,
            oauth_access_token_expire_minutes=dummy_settings.oauth_access_token_expire_minutes,
        )
    )
    return app


def test_get_provider_info(oauth_app):
    """Test GET /auth/oauth/provider endpoint."""
    client = TestClient(oauth_app)

    response = client.get("/auth/oauth/provider")

    assert response.status_code == 200
    assert response.json() == {"provider": "github"}


def test_get_authorization_url(oauth_app):
    """Test POST /auth/oauth/authorize endpoint."""
    client = TestClient(oauth_app)

    response = client.post(
        "/auth/oauth/authorize",
        json={"redirect_uri": "https://example.com/callback"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "authorization_url" in data
    assert "github.com" in data["authorization_url"]
    assert "client_id=test-client-id" in data["authorization_url"]
    assert "redirect_uri=https://example.com/callback" in data["authorization_url"]


def test_oauth_token_exchange_with_custom_role_resolver(dummy_settings, monkeypatch):
    """Test POST /auth/oauth/token with custom role resolver."""

    async def fake_exchange(**_: str) -> str:
        return "provider-access-token"

    async def fake_user_info(**_: str) -> dict[str, str]:
        return {"email": "user@example.com"}

    def fake_extract(user_info: dict[str, str]) -> str:
        return user_info["email"]

    recorded = SimpleNamespace(roles=None, email=None)

    async def custom_role_resolver(user_email: str) -> list[str]:
        recorded.email = user_email
        return ["custom", "special"]

    def fake_create_token(**kwargs) -> str:
        recorded.roles = kwargs.get("roles")
        return "signed-jwt-token"

    monkeypatch.setattr(
        "lib_auth.routers.oauth.exchange_code_for_provider_token",
        fake_exchange,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.get_user_info_from_provider",
        fake_user_info,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.extract_user_email",
        fake_extract,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.create_access_token",
        fake_create_token,
    )

    app = FastAPI()
    app.include_router(
        create_oauth_router(
            oauth_provider=dummy_settings.oauth_provider,
            oauth_client_id=dummy_settings.oauth_client_id,
            oauth_client_secret=dummy_settings.oauth_client_secret,
            oauth_secret_key=dummy_settings.oauth_secret_key,
            oauth_access_token_expire_minutes=dummy_settings.oauth_access_token_expire_minutes,
            user_role_resolver=custom_role_resolver,
        )
    )

    client = TestClient(app)
    response = client.post(
        "/auth/oauth/token",
        json={"code": "auth-code-123", "redirect_uri": "https://example.com/callback"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] == "signed-jwt-token"
    assert data["token_type"] == "bearer"
    assert recorded.email == "user@example.com"
    assert recorded.roles == ["custom", "special"]


def test_oauth_router_with_custom_provider_config(dummy_settings, monkeypatch):
    """Test OAuth router with custom provider configuration."""

    async def fake_exchange(**_: str) -> str:
        return "provider-token"

    async def fake_user_info(**_: str) -> dict[str, str]:
        return {"email": "custom@example.com"}

    def fake_extract(user_info: dict[str, str]) -> str:
        return user_info["email"]

    def fake_create_token(**kwargs) -> str:
        return "custom-token"

    monkeypatch.setattr(
        "lib_auth.routers.oauth.exchange_code_for_provider_token",
        fake_exchange,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.get_user_info_from_provider",
        fake_user_info,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.extract_user_email",
        fake_extract,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.create_access_token",
        fake_create_token,
    )

    app = FastAPI()
    app.include_router(
        create_oauth_router(
            oauth_provider="custom-sso",
            oauth_client_id=dummy_settings.oauth_client_id,
            oauth_client_secret=dummy_settings.oauth_client_secret,
            oauth_secret_key=dummy_settings.oauth_secret_key,
            oauth_access_token_expire_minutes=dummy_settings.oauth_access_token_expire_minutes,
            oauth_provider_config={
                "authorization_url": "https://custom.com/oauth/authorize",
                "token_url": "https://custom.com/oauth/token",
                "userinfo_url": "https://custom.com/api/user",
                "scope": "email profile",
            },
        )
    )

    client = TestClient(app)

    # Test provider info
    response = client.get("/auth/oauth/provider")
    assert response.status_code == 200
    assert response.json() == {"provider": "custom-sso"}

    # Test authorization URL
    response = client.post(
        "/auth/oauth/authorize",
        json={"redirect_uri": "https://app.com/callback"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "custom.com" in data["authorization_url"]


def test_oauth_router_with_default_role_resolver(dummy_settings, monkeypatch):
    """Test OAuth router with default role resolver (user role)."""

    async def fake_exchange(**_: str) -> str:
        return "provider-token"

    async def fake_user_info(**_: str) -> dict[str, str]:
        return {"email": "user@example.com"}

    def fake_extract(user_info: dict[str, str]) -> str:
        return user_info["email"]

    recorded_roles = None

    def fake_create_token(**kwargs) -> str:
        nonlocal recorded_roles
        recorded_roles = kwargs.get("roles")
        return "jwt-token"

    monkeypatch.setattr(
        "lib_auth.routers.oauth.exchange_code_for_provider_token",
        fake_exchange,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.get_user_info_from_provider",
        fake_user_info,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.extract_user_email",
        fake_extract,
    )
    monkeypatch.setattr(
        "lib_auth.routers.oauth.create_access_token",
        fake_create_token,
    )

    app = FastAPI()
    app.include_router(
        create_oauth_router(
            oauth_provider=dummy_settings.oauth_provider,
            oauth_client_id=dummy_settings.oauth_client_id,
            oauth_client_secret=dummy_settings.oauth_client_secret,
            oauth_secret_key=dummy_settings.oauth_secret_key,
            oauth_access_token_expire_minutes=dummy_settings.oauth_access_token_expire_minutes,
            # No custom role resolver - should use default
        )
    )

    client = TestClient(app)
    response = client.post(
        "/auth/oauth/token",
        json={"code": "code", "redirect_uri": "https://example.com/callback"},
    )

    assert response.status_code == 200
    assert recorded_roles == ["user"]  # Default role

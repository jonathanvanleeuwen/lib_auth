"""Integration tests for authentication dependency with FastAPI."""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from starlette.requests import Request

from lib_auth.auth.authentication import create_auth


@pytest.fixture
def app_with_auth(api_keys_dict, dummy_settings):
    """Create a FastAPI app with authentication configured."""
    app = FastAPI()

    @app.get(
        "/admin",
        dependencies=[
            Depends(
                create_auth(
                    api_keys=api_keys_dict,
                    oauth_secret_key=dummy_settings.oauth_secret_key,
                    allowed_roles=["admin"],
                )
            )
        ],
    )
    def admin_endpoint(request: Request):
        return {"user": request.state.user_info}

    @app.get(
        "/user",
        dependencies=[
            Depends(
                create_auth(
                    api_keys=api_keys_dict,
                    oauth_secret_key=dummy_settings.oauth_secret_key,
                    allowed_roles=["user", "admin"],
                )
            )
        ],
    )
    def user_endpoint(request: Request):
        return {"user": request.state.user_info}

    @app.get(
        "/public",
        dependencies=[
            Depends(
                create_auth(
                    api_keys=api_keys_dict,
                    oauth_secret_key=dummy_settings.oauth_secret_key,
                    allowed_roles=None,
                )
            )
        ],
    )
    def public_endpoint(request: Request):
        return {"user": request.state.user_info}

    return app


def test_api_key_auth_admin_access(app_with_auth):
    """Test that admin API key can access admin endpoint."""
    client = TestClient(app_with_auth)

    response = client.get(
        "/admin",
        headers={"Authorization": "Bearer admin-key-12345"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["user"]["sub"] == "admin"
    assert data["user"]["auth_type"] == "api_key"
    assert "admin" in data["user"]["roles"]


def test_api_key_auth_user_denied_admin(app_with_auth):
    """Test that user API key cannot access admin endpoint."""
    client = TestClient(app_with_auth)

    response = client.get(
        "/admin",
        headers={"Authorization": "Bearer user-key-67890"},
    )

    assert response.status_code == 403


def test_api_key_auth_user_access(app_with_auth):
    """Test that user API key can access user endpoint."""
    client = TestClient(app_with_auth)

    response = client.get(
        "/user",
        headers={"Authorization": "Bearer user-key-67890"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["user"]["sub"] == "alice"
    assert data["user"]["auth_type"] == "api_key"


def test_api_key_auth_admin_as_user(app_with_auth):
    """Test that admin API key can access user endpoint."""
    client = TestClient(app_with_auth)

    response = client.get(
        "/user",
        headers={"Authorization": "Bearer admin-key-12345"},
    )

    assert response.status_code == 200


def test_invalid_api_key(app_with_auth):
    """Test that invalid API key is rejected."""
    client = TestClient(app_with_auth, follow_redirects=False)

    response = client.get(
        "/user",
        headers={"Authorization": "Bearer invalid-key"},
    )

    assert response.status_code == 307  # Redirect to /static/
    assert response.headers["location"] == "/static/"


def test_missing_authorization_header(app_with_auth):
    """Test that missing authorization header redirects."""
    client = TestClient(app_with_auth, follow_redirects=False)

    response = client.get("/user")

    assert response.status_code == 307
    assert response.headers["location"] == "/static/"


def test_invalid_bearer_scheme(app_with_auth):
    """Test that non-Bearer scheme is rejected."""
    client = TestClient(app_with_auth, follow_redirects=False)

    response = client.get(
        "/user",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )

    assert response.status_code == 307
    assert response.headers["location"] == "/static/"


@pytest.mark.asyncio
async def test_auth_dependency_sets_request_state(
    api_keys_dict, dummy_settings, mock_request
):
    """Test that authentication sets request.state correctly."""
    auth_dep = create_auth(
        api_keys=api_keys_dict,
        oauth_secret_key=dummy_settings.oauth_secret_key,
        allowed_roles=["admin"],
    )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="admin-key-12345",
    )
    request = mock_request()

    result = await auth_dep(request, credentials=credentials)

    assert result["sub"] == "admin"
    assert request.state.user_info == result
    assert request.state.auth_token == "admin-key-12345"


@pytest.mark.asyncio
async def test_oauth_token_fallback(
    api_keys_dict, dummy_settings, mock_request, monkeypatch
):
    """Test that auth falls back to OAuth token verification when API key fails."""

    def fake_verify(token: str, *, secret_key: str) -> dict[str, str | list[str]]:
        assert token == "oauth-token-xyz"
        return {
            "sub": "oauth-user@example.com",
            "roles": ["user"],
            "provider": "github",
        }

    monkeypatch.setattr(
        "lib_auth.auth.authentication.verify_access_token",
        fake_verify,
    )

    auth_dep = create_auth(
        api_keys=api_keys_dict,
        oauth_secret_key=dummy_settings.oauth_secret_key,
        allowed_roles=None,
    )

    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="oauth-token-xyz",
    )
    request = mock_request()

    result = await auth_dep(request, credentials=credentials)

    assert result["sub"] == "oauth-user@example.com"
    assert result["auth_type"] == "oauth"
    assert result["provider"] == "github"

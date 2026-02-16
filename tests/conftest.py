"""Shared test fixtures and configuration for all tests."""

from __future__ import annotations

import pytest
from starlette.requests import Request


@pytest.fixture
def dummy_settings():
    """Dummy settings object for testing."""

    class DummySettings:
        def __init__(self) -> None:
            self.api_keys: dict[str, dict[str, list[str] | str]] = {}
            self.oauth_provider = "github"
            self.oauth_client_id = "test-client-id"
            self.oauth_client_secret = "test-client-secret"
            self.oauth_secret_key = "test-secret-key-for-jwt-signing"
            self.oauth_access_token_expire_minutes = 60

    return DummySettings()


@pytest.fixture
def mock_request():
    """Create a mock FastAPI/Starlette Request object."""

    def _build_request(path: str = "/", method: str = "GET") -> Request:
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
        }

        async def _receive() -> dict[str, bytes]:
            return {"type": "http.request"}

        return Request(scope, receive=_receive)

    return _build_request


@pytest.fixture
def api_keys_dict():
    """Sample API keys dictionary for testing."""
    from lib_auth.utils.auth_utils import hash_api_key

    return {
        hash_api_key("admin-key-12345"): {
            "username": "admin",
            "roles": ["admin", "user"],
        },
        hash_api_key("user-key-67890"): {
            "username": "alice",
            "roles": ["user"],
        },
    }

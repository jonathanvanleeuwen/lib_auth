"""Unit tests for JWT token creation and verification."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from lib_auth.auth.oauth_auth import create_access_token, verify_access_token


def test_create_access_token_basic():
    """Test creating a basic access token with user data."""
    token = create_access_token(
        data={"sub": "user@example.com"},
        secret_key="test-secret-key",
        expire_minutes=60,
        roles=["user"],
    )

    assert isinstance(token, str)
    assert len(token) > 0


def test_access_token_roundtrip():
    """Test creating and verifying a token maintains data integrity."""
    secret_key = "super-secret-signing-key-1234567890"
    user_email = "user@example.com"
    roles = ["user", "admin"]

    token = create_access_token(
        data={"sub": user_email},
        secret_key=secret_key,
        expire_minutes=1,
        roles=roles,
    )

    payload = verify_access_token(token, secret_key=secret_key)

    assert payload["sub"] == user_email
    assert payload["roles"] == roles


def test_access_token_with_custom_data():
    """Test token creation with custom data fields."""
    secret_key = "test-key"
    custom_data = {
        "sub": "user@example.com",
        "org_id": "org-123",
        "department": "engineering",
    }

    token = create_access_token(
        data=custom_data,
        secret_key=secret_key,
        expire_minutes=30,
        roles=["user"],
    )

    payload = verify_access_token(token, secret_key=secret_key)

    assert payload["sub"] == "user@example.com"
    assert payload["org_id"] == "org-123"
    assert payload["department"] == "engineering"
    assert payload["roles"] == ["user"]


def test_verify_access_token_with_wrong_secret():
    """Test that verification fails with incorrect secret key."""
    token = create_access_token(
        data={"sub": "user@example.com"},
        secret_key="correct-secret",
        expire_minutes=60,
        roles=["user"],
    )

    with pytest.raises(HTTPException) as exc_info:
        verify_access_token(token, secret_key="wrong-secret")

    assert exc_info.value.status_code == 401


def test_verify_invalid_token_format():
    """Test that verification fails with malformed token."""
    with pytest.raises(HTTPException) as exc_info:
        verify_access_token("not.a.valid.token", secret_key="secret")

    assert exc_info.value.status_code == 401


def test_access_token_with_empty_roles():
    """Test creating token with empty roles list."""
    token = create_access_token(
        data={"sub": "user@example.com"},
        secret_key="secret",
        expire_minutes=60,
        roles=[],
    )

    payload = verify_access_token(token, secret_key="secret")
    # Empty roles list is not added to token (falsy check)
    assert "roles" not in payload


def test_access_token_with_multiple_roles():
    """Test token with multiple roles."""
    roles = ["user", "admin", "moderator", "editor"]
    token = create_access_token(
        data={"sub": "super-user@example.com"},
        secret_key="secret",
        expire_minutes=60,
        roles=roles,
    )

    payload = verify_access_token(token, secret_key="secret")
    assert payload["roles"] == roles

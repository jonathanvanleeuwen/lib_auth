"""Unit tests for role resolution logic."""

from __future__ import annotations

import pytest

from lib_auth.utils.auth_utils import default_user_role_resolver, resolve_user_roles


def test_default_user_role_resolver():
    """Test that default resolver returns 'user' role."""
    roles = default_user_role_resolver("any@example.com")

    assert roles == ["user"]


def test_default_role_resolver_ignores_email():
    """Test that default resolver ignores the email parameter."""
    email1 = default_user_role_resolver("user1@example.com")
    email2 = default_user_role_resolver("user2@example.com")
    empty = default_user_role_resolver("")

    assert email1 == email2 == empty == ["user"]


@pytest.mark.asyncio
async def test_resolve_user_roles_with_sync_resolver():
    """Test resolve_user_roles with synchronous role resolver."""

    def sync_resolver(user_email: str) -> list[str]:
        if user_email == "admin@example.com":
            return ["admin", "user"]
        return ["user"]

    roles = await resolve_user_roles(sync_resolver, "admin@example.com")
    assert roles == ["admin", "user"]

    roles = await resolve_user_roles(sync_resolver, "regular@example.com")
    assert roles == ["user"]


@pytest.mark.asyncio
async def test_resolve_user_roles_with_async_resolver():
    """Test resolve_user_roles with asynchronous role resolver."""

    async def async_resolver(user_email: str) -> list[str]:
        if "premium" in user_email:
            return ["premium", "user"]
        return ["user"]

    roles = await resolve_user_roles(async_resolver, "premium@example.com")
    assert roles == ["premium", "user"]

    roles = await resolve_user_roles(async_resolver, "basic@example.com")
    assert roles == ["user"]


@pytest.mark.asyncio
async def test_resolve_user_roles_with_none_resolver():
    """Test resolve_user_roles falls back to default when resolver is None."""
    roles = await resolve_user_roles(None, "any@example.com")

    assert roles == ["user"]


@pytest.mark.asyncio
async def test_resolve_user_roles_returns_default_when_empty():
    """Test that empty roles list returns default 'user' role."""

    def empty_resolver(_: str) -> list[str]:
        return []

    roles = await resolve_user_roles(empty_resolver, "user@example.com")

    assert roles == ["user"]


@pytest.mark.asyncio
async def test_resolve_user_roles_with_multiple_roles():
    """Test resolver returning multiple roles."""

    def multi_role_resolver(user_email: str) -> list[str]:
        return ["user", "editor", "moderator", "admin"]

    roles = await resolve_user_roles(multi_role_resolver, "super@example.com")

    assert roles == ["user", "editor", "moderator", "admin"]


@pytest.mark.asyncio
async def test_resolve_user_roles_async_with_database_simulation():
    """Simulate async database lookup for roles."""

    async def db_role_lookup(user_email: str) -> list[str]:
        # Simulate database lookup
        fake_db = {
            "alice@example.com": ["admin", "user"],
            "bob@example.com": ["user"],
            "charlie@example.com": ["moderator", "user"],
        }
        return fake_db.get(user_email, ["user"])

    alice_roles = await resolve_user_roles(db_role_lookup, "alice@example.com")
    assert alice_roles == ["admin", "user"]

    bob_roles = await resolve_user_roles(db_role_lookup, "bob@example.com")
    assert bob_roles == ["user"]

    unknown_roles = await resolve_user_roles(db_role_lookup, "unknown@example.com")
    assert unknown_roles == ["user"]

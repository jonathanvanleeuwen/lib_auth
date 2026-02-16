"""Unit tests for API key hashing and utilities."""

from __future__ import annotations

from lib_auth.utils.auth_utils import hash_api_key


def test_hash_api_key_consistent():
    """Test that the same API key always produces the same hash."""
    api_key = "my-secret-api-key"
    hash1 = hash_api_key(api_key)
    hash2 = hash_api_key(api_key)

    assert hash1 == hash2


def test_hash_api_key_different_keys():
    """Test that different API keys produce different hashes."""
    hash1 = hash_api_key("key-one")
    hash2 = hash_api_key("key-two")

    assert hash1 != hash2


def test_hash_api_key_returns_hex_string():
    """Test that hash is a valid hexadecimal string."""
    api_key = "test-key"
    hashed = hash_api_key(api_key)

    assert isinstance(hashed, str)
    assert len(hashed) == 64  # SHA256 produces 64 hex characters
    assert all(c in "0123456789abcdef" for c in hashed)


def test_hash_api_key_empty_string():
    """Test hashing an empty string."""
    hashed = hash_api_key("")

    assert isinstance(hashed, str)
    assert len(hashed) == 64


def test_hash_api_key_special_characters():
    """Test hashing keys with special characters."""
    special_key = "key!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
    hashed = hash_api_key(special_key)

    assert isinstance(hashed, str)
    assert len(hashed) == 64


def test_hash_api_key_unicode():
    """Test hashing keys with unicode characters."""
    unicode_key = "key-with-émojis-🔐🔑"
    hashed = hash_api_key(unicode_key)

    assert isinstance(hashed, str)
    assert len(hashed) == 64


def test_hash_api_key_case_sensitive():
    """Test that hashing is case-sensitive."""
    hash_lower = hash_api_key("mykey")
    hash_upper = hash_api_key("MYKEY")
    hash_mixed = hash_api_key("MyKey")

    assert hash_lower != hash_upper
    assert hash_lower != hash_mixed
    assert hash_upper != hash_mixed

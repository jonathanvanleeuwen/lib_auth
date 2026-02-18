"""Utilities for JWT token verification."""

import json
import time
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, status


async def fetch_jwks(
    jwks_url: str,
    cache: dict[str, tuple[dict[str, Any], float]],
    cache_key: str = "default",
    cache_duration: int = 3600,
    error_detail: str = "Failed to retrieve public keys",
) -> dict[str, Any]:
    """
    Fetch and cache JWKS (JSON Web Key Set) from a URL.

    Args:
        jwks_url: URL to fetch JWKS from
        cache: Cache dictionary to store JWKS
        cache_key: Key to use in cache dictionary
        cache_duration: How long to cache JWKS in seconds
        error_detail: Error message if fetch fails

    Returns:
        JWKS dictionary

    Raises:
        HTTPException: If fetching JWKS fails
    """
    if cache_key in cache:
        jwks_data, expires_at = cache[cache_key]
        if time.time() < expires_at:
            return jwks_data

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(jwks_url, timeout=10.0)
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=error_detail,
            ) from e

    jwks_data = response.json()
    cache[cache_key] = (jwks_data, time.time() + cache_duration)

    return jwks_data


def extract_public_key_from_jwks(token: str, jwks: dict[str, Any]) -> Any:
    """
    Extract public key from JWKS based on token's kid header.

    Args:
        token: JWT token
        jwks: JWKS dictionary containing public keys

    Returns:
        Public key object

    Raises:
        HTTPException: If kid is missing or key not found
    """
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    if not kid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing key ID (kid)",
        )

    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token signing key not found",
    )


def handle_jwt_exceptions(e: Exception, provider_name: str) -> None:
    """
    Handle common JWT exceptions with standardized error messages.

    Args:
        e: The exception to handle
        provider_name: Name of the provider (for logging)

    Raises:
        HTTPException: Always raises with appropriate status and detail
    """
    import logging

    logger = logging.getLogger(__name__)

    if isinstance(e, jwt.ExpiredSignatureError):
        logger.warning("%s token expired", provider_name)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        ) from e
    elif isinstance(e, jwt.InvalidTokenError):
        logger.warning("%s token invalid: %s", provider_name, e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from e
    else:
        raise

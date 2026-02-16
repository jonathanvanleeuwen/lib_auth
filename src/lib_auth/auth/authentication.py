import logging
from typing import Any

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lib_auth.auth.oauth_auth import verify_access_token
from lib_auth.utils.auth_utils import hash_api_key

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)
_security_bearer = Security(bearer_scheme)


def _check_roles(user_roles: list[str], allowed_roles: list[str] | None) -> None:
    if allowed_roles and not any(role in user_roles for role in allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not have required role",
        )


def _try_api_key_auth(
    token: str,
    api_keys: dict[str, dict[str, Any]],
    allowed_roles: list[str] | None,
) -> dict[str, Any] | None:
    logger.debug("Attempting API key authentication")
    hashed_token = hash_api_key(token)
    user_info = api_keys.get(hashed_token)
    if not user_info:
        logger.debug("API key not found in configured keys")
        return None

    username = user_info.get("username")
    roles = list(user_info.get("roles", []))
    _check_roles(roles, allowed_roles)

    logger.info("API key authentication successful: user=%s roles=%s", username, roles)
    return {
        "sub": username,
        "auth_type": "api_key",
        "roles": roles,
    }


def _try_oauth_auth(
    token: str,
    oauth_secret_key: str,
    allowed_roles: list[str] | None,
) -> dict[str, Any] | None:
    logger.debug("Attempting OAuth token authentication")
    try:
        payload = verify_access_token(token, secret_key=oauth_secret_key)
    except HTTPException as exc:
        logger.debug("OAuth token verification failed: %s", exc.detail)
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            detail="OAuth authentication failed",
            headers={"Location": "/static/"},
        ) from exc

    user_email = payload.get("sub")
    if not user_email:
        logger.warning("OAuth token missing 'sub' claim")
        return None

    roles = payload.get("roles", [])
    _check_roles(roles, allowed_roles)
    provider = payload.get("provider", "unknown")
    logger.info(
        "OAuth authentication successful: user=%s provider=%s roles=%s",
        user_email,
        provider,
        roles,
    )
    return {
        "sub": user_email,
        "auth_type": "oauth",
        "provider": provider,
        "roles": roles,
    }


def create_auth(
    api_keys: dict[str, dict[str, Any]],
    oauth_secret_key: str,
    allowed_roles: list[str] | None = None,
) -> Any:
    async def bearer_auth(
        request: Request,
        credentials: HTTPAuthorizationCredentials = _security_bearer,
    ) -> dict[str, Any]:
        if not credentials or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                detail="Authentication required",
                headers={"Location": "/static/"},
            )

        token = credentials.credentials
        user_info = _try_api_key_auth(token, api_keys, allowed_roles)
        if not user_info:
            user_info = _try_oauth_auth(token, oauth_secret_key, allowed_roles)

        if not user_info:
            logger.warning("Authentication failed: invalid credentials")
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                detail="Invalid authentication credentials",
                headers={"Location": "/static/"},
            )

        request.state.user_info = user_info
        request.state.auth_token = token
        return user_info

    return bearer_auth

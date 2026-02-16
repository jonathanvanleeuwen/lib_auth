import logging
from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lib_auth.auth.oauth_auth import verify_access_token
from lib_auth.settings import Settings
from lib_auth.settings import get_settings
from lib_auth.utils.auth_utils import hash_api_key

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)
_security_bearer = Security(bearer_scheme)
_depends_settings = Depends(get_settings)


def _check_roles(user_roles: list[str], allowed_roles: list[str] | None) -> None:
    if allowed_roles and not any(role in user_roles for role in allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not have required role",
        )


def _try_api_key_auth(
    token: str,
    settings: Settings,
    allowed_roles: list[str] | None,
) -> dict[str, Any] | None:
    hashed_token = hash_api_key(token)
    user_info = settings.api_keys.get(hashed_token)
    if not user_info:
        return None

    username = user_info.get("username")
    roles = user_info.get("roles", [])
    _check_roles(roles, allowed_roles)

    return {
        "sub": username,
        "auth_type": "api_key",
        "roles": roles,
    }


def _try_oauth_auth(
    token: str,
    allowed_roles: list[str] | None,
) -> dict[str, Any] | None:
    payload = verify_access_token(token)
    user_email = payload.get("sub")
    if not user_email:
        return None
    roles = payload.get("roles", [])
    _check_roles(roles, allowed_roles)
    return {
        "sub": user_email,
        "auth_type": "oauth",
        "provider": payload.get("provider", "unknown"),
        "roles": roles,
    }


def create_auth(allowed_roles: list[str] | None = None) -> Callable:
    async def bearer_auth(
        request: Request,
        credentials: HTTPAuthorizationCredentials = _security_bearer,
        settings: Settings = _depends_settings,
    ) -> dict[str, Any]:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing Authorization header",
            )

        token = credentials.credentials
        user_info = _try_api_key_auth(token, settings, allowed_roles)
        if user_info is None:
            user_info = _try_oauth_auth(token, allowed_roles)

        if user_info is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )

        request.state.user_info = user_info
        request.state.auth_token = token
        return user_info

    return bearer_auth


auth_admin = create_auth(allowed_roles=["admin"])
auth_user = create_auth(allowed_roles=["admin", "user"])
auth_any = create_auth()

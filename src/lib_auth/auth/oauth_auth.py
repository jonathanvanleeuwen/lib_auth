from datetime import UTC, datetime, timedelta
from typing import Any

import jwt  # type: ignore[import-not-found]
from fastapi import HTTPException, status

from documentsearch.settings import get_settings


def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
    roles: list[str] | None = None,
) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.oauth_access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    if roles:
        to_encode["roles"] = roles
    return jwt.encode(to_encode, settings.oauth_secret_key, algorithm="HS256")


def verify_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.oauth_secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from exc

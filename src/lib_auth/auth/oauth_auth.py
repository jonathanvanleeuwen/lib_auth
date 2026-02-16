from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import HTTPException, status

ALGORITHM = "HS256"


def create_access_token(
    *,
    data: dict[str, Any],
    secret_key: str,
    expire_minutes: int,
    expires_delta: timedelta | None = None,
    roles: list[str] | None = None,
) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=expire_minutes))
    to_encode.update({"exp": expire})
    if roles:
        to_encode["roles"] = roles
    return jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)


def verify_access_token(token: str, *, secret_key: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, secret_key, algorithms=[ALGORITHM])
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

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Awaitable, Callable


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def default_user_role_resolver(_: str) -> list[str]:
    return ["user"]


async def resolve_user_roles(
    user_role_resolver: Callable[[str], list[str] | Awaitable[list[str]]] | None,
    user_email: str,
) -> list[str]:
    resolver = user_role_resolver or default_user_role_resolver
    roles = resolver(user_email)
    if inspect.isawaitable(roles):
        roles = await roles
    if not roles:
        return ["user"]
    return roles

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastapi import HTTPException, status

from lib_auth.auth.oauth_providers import OAUTH_PROVIDERS

logger = logging.getLogger(__name__)


def get_oauth_config(provider: str) -> dict[str, str]:
    if provider not in OAUTH_PROVIDERS:
        raise ValueError(f"Unsupported OAuth provider: {provider}")
    return OAUTH_PROVIDERS[provider]


def build_authorization_url(
    *,
    provider: str,
    client_id: str,
    redirect_uri: str,
) -> str:
    oauth_config = get_oauth_config(provider)
    return (
        f"{oauth_config['authorization_url']}"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope={oauth_config['scope']}"
    )


async def exchange_code_for_provider_token(
    *,
    provider: str,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> str:
    oauth_config = get_oauth_config(provider)
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                oauth_config["token_url"],
                data=token_data,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            oauth_tokens = response.json()
        except httpx.HTTPError as exc:
            logger.error("Failed to exchange code for token: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to exchange authorization code",
            ) from exc

    provider_access_token = oauth_tokens.get("access_token")
    if not provider_access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No access token in response",
        )

    return provider_access_token


async def get_user_info_from_provider(
    *,
    provider: str,
    provider_access_token: str,
) -> dict[str, Any]:
    oauth_config = get_oauth_config(provider)

    async with httpx.AsyncClient() as client:
        try:
            user_response = await client.get(
                oauth_config["userinfo_url"],
                headers={"Authorization": f"Bearer {provider_access_token}"},
            )
            user_response.raise_for_status()
            user_info = user_response.json()

            if provider == "github" and not user_info.get("email"):
                emails_response = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {provider_access_token}"},
                )
                emails_response.raise_for_status()
                emails = emails_response.json()

                primary_email = next(
                    (
                        email_entry["email"]
                        for email_entry in emails
                        if email_entry.get("primary") and email_entry.get("verified")
                    ),
                    None,
                )
                if not primary_email:
                    primary_email = next(
                        (
                            email_entry["email"]
                            for email_entry in emails
                            if email_entry.get("verified")
                        ),
                        None,
                    )

                if primary_email:
                    user_info["email"] = primary_email

            return user_info
        except httpx.HTTPError as exc:
            logger.error("Failed to get user info: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to retrieve user information",
            ) from exc


def extract_user_email(user_info: dict[str, Any]) -> str:
    user_email = user_info.get("email") or user_info.get("mail")
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not found in user info",
        )
    return user_email

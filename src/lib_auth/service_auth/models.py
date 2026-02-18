"""Service authentication models and configuration."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ServiceAuthProviderType(StrEnum):
    """Supported service authentication providers."""

    AZURE = "azure"
    GOOGLE = "google"
    GITHUB = "github"


class ServiceAuthConfig(BaseModel):
    """Configuration for service authentication provider."""

    provider: ServiceAuthProviderType
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    private_key: str | None = None
    project_id: str | None = None
    app_id: str | None = None
    target_audience: str | None = None
    allowed_audiences: list[str] = Field(default_factory=list)
    issuer: str | None = None


class ServiceTokenPayload(BaseModel):
    """Service authentication token payload."""

    sub: str
    aud: str | list[str]
    iss: str
    exp: int
    iat: int
    service_name: str
    roles: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

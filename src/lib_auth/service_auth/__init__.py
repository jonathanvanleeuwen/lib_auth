"""Service-to-service authentication using short-lived JWT tokens."""

from lib_auth.service_auth.authentication import create_service_auth
from lib_auth.service_auth.base_provider import ServiceAuthProvider
from lib_auth.service_auth.provider_factory import get_provider

__all__ = ["create_service_auth", "get_provider", "ServiceAuthProvider"]

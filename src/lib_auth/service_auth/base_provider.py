"""Base provider interface for service authentication."""

from abc import ABC, abstractmethod

from lib_auth.service_auth.models import ServiceAuthConfig, ServiceTokenPayload


class ServiceAuthProvider(ABC):
    """Abstract base class for service authentication providers."""

    def __init__(self, config: ServiceAuthConfig):
        self.config = config

    @abstractmethod
    async def get_token(self, target_audience: str, service_name: str) -> str:
        """
        Get a JWT token for authenticating to a target service.

        Args:
            target_audience: The target service identifier (audience claim)
            service_name: Name of the requesting service (subject claim)

        Returns:
            Signed JWT token as a string
        """

    @abstractmethod
    async def verify_token(self, token: str) -> ServiceTokenPayload:
        """
        Verify a JWT token from another service.

        Args:
            token: The JWT token to verify

        Returns:
            Decoded and verified token payload

        Raises:
            HTTPException: If token is invalid or expired
        """

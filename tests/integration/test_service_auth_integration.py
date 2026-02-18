"""Integration tests for service authentication."""

import time

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from lib_auth.service_auth import create_service_auth
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType


def generate_rsa_keypair():
    """Generate RSA key pair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return private_pem


@pytest.fixture
def github_private_key():
    """Generate a test RSA private key."""
    return generate_rsa_keypair()


@pytest.fixture
def github_service_config(github_private_key):
    """Create test GitHub service configuration."""
    return ServiceAuthConfig(
        provider=ServiceAuthProviderType.GITHUB,
        app_id="123456",
        private_key=github_private_key,
        allowed_audiences=["test-service"],
    )


@pytest.fixture
def test_app(github_service_config):
    """Create test FastAPI app with service authentication."""
    from fastapi import Request

    app = FastAPI()

    @app.get(
        "/protected",
        dependencies=[Depends(create_service_auth(config=github_service_config))],
    )
    def protected_endpoint(request: Request):
        service_info = request.state.service_info
        return {
            "message": "success",
            "service": service_info.service_name,
            "roles": service_info.roles,
        }

    @app.get(
        "/restricted",
        dependencies=[
            Depends(
                create_service_auth(
                    config=github_service_config,
                    allowed_services=["service-a"],
                )
            )
        ],
    )
    def restricted_endpoint():
        return {"message": "restricted access granted"}

    @app.get(
        "/role-protected",
        dependencies=[
            Depends(
                create_service_auth(
                    config=github_service_config,
                    required_roles=["Service.Admin"],
                )
            )
        ],
    )
    def role_protected_endpoint():
        return {"message": "admin access granted"}

    return app


@pytest.mark.asyncio
async def test_github_service_auth_success(
    test_app, github_service_config, github_private_key
):
    """Test successful service authentication with GitHub provider."""
    client = TestClient(test_app)

    now = int(time.time())
    token_payload = {
        "iss": f"github-app-{github_service_config.app_id}",
        "sub": "service-a",
        "aud": "test-service",
        "iat": now,
        "exp": now + 600,
        "service_name": "service-a",
        "github_app_id": github_service_config.app_id,
    }

    token = jwt.encode(token_payload, github_private_key, algorithm="RS256")

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "success"
    assert response.json()["service"] == "service-a"


def test_github_service_auth_no_token(test_app):
    """Test service authentication fails without token."""
    client = TestClient(test_app)

    response = client.get("/protected")

    assert response.status_code == 401
    assert "detail" in response.json()


def test_github_service_auth_invalid_token(test_app):
    """Test service authentication fails with invalid token."""
    client = TestClient(test_app)

    response = client.get(
        "/protected",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


def test_github_service_auth_expired_token(
    test_app, github_private_key, github_service_config
):
    """Test service authentication fails with expired token."""
    client = TestClient(test_app)

    now = int(time.time())
    token_payload = {
        "iss": f"github-app-{github_service_config.app_id}",
        "sub": "service-a",
        "aud": "test-service",
        "iat": now - 700,
        "exp": now - 100,
        "service_name": "service-a",
        "github_app_id": github_service_config.app_id,
    }

    token = jwt.encode(token_payload, github_private_key, algorithm="RS256")

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_github_service_auth_allowed_services(
    test_app, github_private_key, github_service_config
):
    """Test service authentication with allowed_services restriction."""
    client = TestClient(test_app)

    now = int(time.time())

    token_payload_allowed = {
        "iss": f"github-app-{github_service_config.app_id}",
        "sub": "service-a",
        "aud": "test-service",
        "iat": now,
        "exp": now + 600,
        "service_name": "service-a",
        "github_app_id": github_service_config.app_id,
    }

    token_allowed = jwt.encode(
        token_payload_allowed, github_private_key, algorithm="RS256"
    )

    response = client.get(
        "/restricted",
        headers={"Authorization": f"Bearer {token_allowed}"},
    )

    assert response.status_code == 200

    token_payload_denied = {
        "iss": f"github-app-{github_service_config.app_id}",
        "sub": "service-b",
        "aud": "test-service",
        "iat": now,
        "exp": now + 600,
        "service_name": "service-b",
        "github_app_id": github_service_config.app_id,
    }

    token_denied = jwt.encode(
        token_payload_denied, github_private_key, algorithm="RS256"
    )

    response = client.get(
        "/restricted",
        headers={"Authorization": f"Bearer {token_denied}"},
    )

    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"].lower()


def test_github_service_auth_required_roles(
    test_app, github_private_key, github_service_config
):
    """Test service authentication with required_roles restriction."""
    client = TestClient(test_app)

    now = int(time.time())

    token_payload_no_roles = {
        "iss": f"github-app-{github_service_config.app_id}",
        "sub": "service-a",
        "aud": "test-service",
        "iat": now,
        "exp": now + 600,
        "service_name": "service-a",
        "github_app_id": github_service_config.app_id,
    }

    token_no_roles = jwt.encode(
        token_payload_no_roles, github_private_key, algorithm="RS256"
    )

    response = client.get(
        "/role-protected",
        headers={"Authorization": f"Bearer {token_no_roles}"},
    )

    assert response.status_code == 403
    assert "required role" in response.json()["detail"].lower()

    token_payload_with_roles = {
        "iss": f"github-app-{github_service_config.app_id}",
        "sub": "service-a",
        "aud": "test-service",
        "iat": now,
        "exp": now + 600,
        "service_name": "service-a",
        "github_app_id": github_service_config.app_id,
        "roles": ["Service.Admin"],
    }

    token_with_roles = jwt.encode(
        token_payload_with_roles, github_private_key, algorithm="RS256"
    )

    response = client.get(
        "/role-protected",
        headers={"Authorization": f"Bearer {token_with_roles}"},
    )

    assert response.status_code == 200

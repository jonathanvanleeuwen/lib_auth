# Service-to-Service Authentication - Quick Reference

## When to Use This

✅ **Use service-to-service authentication when:**
- Microservices need to call each other
- You want short-lived tokens (10-60 minutes)
- You need cloud-native identity management
- You want zero-trust security architecture

❌ **Don't use this for:**
- User authentication (use OAuth 2.0 instead)
- Long-running background jobs (use API keys)
- Public APIs (use API keys with rate limiting)

## Provider Comparison

| Feature | Azure | Google | GitHub |
|---------|-------|--------|--------|
| Token Lifetime | 60-90 min | 60 min | 10 min |
| Setup Complexity | Medium | Low | Low |
| Key Rotation | Automatic | Manual | Manual |
| Best For | Azure/Microsoft | GCP/Google | GitHub Apps |

## Quick Setup

### 1. Choose Provider & Configure

```python
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType

# Azure
config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.AZURE,
    tenant_id="your-tenant-id",
    client_id="your-client-id",
    client_secret="your-client-secret",
    allowed_audiences=["api://your-service"],
)

# Google
config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.GOOGLE,
    private_key=open("service-account.json").read(),
    client_id="service@project.iam.gserviceaccount.com",
)

# GitHub
config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.GITHUB,
    app_id="123456",
    private_key=open("github-app.pem").read(),
)
```

### 2. Protect Your Endpoints (Service Receiving Calls)

```python
from fastapi import Depends, FastAPI
from lib_auth.service_auth import create_service_auth

app = FastAPI()

@app.get(
    "/api/data",
    dependencies=[Depends(create_service_auth(config=config))]
)
async def get_data():
    return {"data": "protected"}
```

### 3. Call Other Services (Service Making Calls)

```python
from lib_auth.service_auth.utils import get_service_token
import httpx

# Get token
token = await get_service_token(
    config=config,
    target_audience="api://other-service",
    service_name="my-service",
)

# Call other service
async with httpx.AsyncClient() as client:
    response = await client.get(
        "https://other-service.com/api/data",
        headers={"Authorization": f"Bearer {token}"},
    )
```

## Common Patterns

### Restrict Allowed Callers

```python
@app.get(
    "/admin",
    dependencies=[
        Depends(create_service_auth(
            config=config,
            allowed_services=["service-a", "service-b"]
        ))
    ]
)
async def admin():
    return {"message": "restricted"}
```

### Require Specific Roles

```python
@app.get(
    "/admin",
    dependencies=[
        Depends(create_service_auth(
            config=config,
            required_roles=["Service.Admin"]
        ))
    ]
)
async def admin():
    return {"message": "admin only"}
```

### Get Caller Information

```python
@app.get("/api/data")
async def get_data(request: Request):
    service_info = request.state.service_info

    # Available fields:
    # - service_info.service_name
    # - service_info.sub
    # - service_info.aud
    # - service_info.roles
    # - service_info.metadata

    return {"caller": service_info.service_name}
```

## Environment Variables Pattern

```bash
# .env
SERVICE_AUTH_PROVIDER=azure
SERVICE_AUTH_TENANT_ID=xxx
SERVICE_AUTH_CLIENT_ID=xxx
SERVICE_AUTH_CLIENT_SECRET=xxx
SERVICE_AUTH_ALLOWED_AUDIENCES=api://my-service
```

```python
import os
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType

config = ServiceAuthConfig(
    provider=ServiceAuthProviderType(os.environ["SERVICE_AUTH_PROVIDER"]),
    tenant_id=os.getenv("SERVICE_AUTH_TENANT_ID"),
    client_id=os.getenv("SERVICE_AUTH_CLIENT_ID"),
    client_secret=os.getenv("SERVICE_AUTH_CLIENT_SECRET"),
    allowed_audiences=os.getenv("SERVICE_AUTH_ALLOWED_AUDIENCES", "").split(","),
)
```

## Security Best Practices

1. ✅ **Always validate audience** - Set `allowed_audiences` to prevent token reuse
2. ✅ **Use short token lifetimes** - Default lifetimes are secure (10-90 min)
3. ✅ **Restrict allowed services** - Use `allowed_services` parameter
4. ✅ **Store credentials in secrets manager** - Never commit to source control
5. ✅ **Monitor authentication events** - Enable logging at INFO level
6. ✅ **Rotate secrets regularly** - Azure does this automatically

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| Token expired | Token older than lifetime | Tokens auto-refresh; check system clock |
| Invalid audience | Mismatch in `aud` claim | Verify `allowed_audiences` config |
| Service not authorized | Wrong service name | Check `allowed_services` list |
| Token signing key not found | Can't reach identity provider | Check network/credentials |

## Full Example

See `examples/service_to_service_example.py` for a complete working example.

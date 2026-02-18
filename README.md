# lib_auth

FastAPI authentication library supporting API keys and OAuth 2.0 (GitHub, Google, Microsoft, GitLab, LinkedIn, Discord).

<!-- Pytest Coverage Comment:Begin -->
<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/README.md"><img alt="Coverage" src="https://img.shields.io/badge/Coverage-66%25-yellow.svg" /></a><details><summary>Coverage Report </summary><table><tr><th>File</th><th>Stmts</th><th>Miss</th><th>Cover</th><th>Missing</th></tr><tbody><tr><td colspan="5"><b>src/lib_auth</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/__init__.py">__init__.py</a></td><td>1</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/auth</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/__init__.py">__init__.py</a></td><td>0</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/authentication.py">authentication.py</a></td><td>55</td><td>4</td><td>93%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/authentication.py#L65-L66">65&ndash;66</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/authentication.py#L107-L108">107&ndash;108</a></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/oauth_auth.py">oauth_auth.py</a></td><td>26</td><td>2</td><td>92%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/oauth_auth.py#L44-L45">44&ndash;45</a></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/oauth_providers.py">oauth_providers.py</a></td><td>3</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/secrets_b64.py">secrets_b64.py</a></td><td>34</td><td>34</td><td>0%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/secrets_b64.py#L1-L52">1&ndash;52</a></td></tr><tr><td colspan="5"><b>src/lib_auth/models</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/models/__init__.py">__init__.py</a></td><td>0</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/models/oauth.py">oauth.py</a></td><td>9</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/routers</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/routers/oauth.py">oauth.py</a></td><td>31</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/utils</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/utils/auth_utils.py">auth_utils.py</a></td><td>20</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/workers</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/__init__.py">__init__.py</a></td><td>0</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py">oauth_service.py</a></td><td>57</td><td>41</td><td>28%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L16">16</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L44-L81">44&ndash;81</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L89-L138">89&ndash;138</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L145-L151">145&ndash;151</a></td></tr><tr><td><b>TOTAL</b></td><td><b>236</b></td><td><b>81</b></td><td><b>66%</b></td><td>&nbsp;</td></tr></tbody></table></details>
<!-- Pytest Coverage Comment:End -->


## Installation

**Install newest version:**
```bash
uv pip install "git+https://github.com/jonathanvanleeuwen/lib_auth.git"
```
**Install specific version:**
```bash
uv pip install "git+https://github.com/jonathanvanleeuwen/lib_auth.git@v1.0.1"
```

**Add to `pyproject.toml`:**
The @version is optional, but recommended (choose the newest version first!)

```toml
[project]
dependencies = [
    "lib_auth @ git+https://github.com/jonathanvanleeuwen/lib_auth.git@v1.0.1",
]
```

**Add to `requirements.txt`:**
The @version is optional, but recommended (choose the newest version first!)
```text
lib_auth @ git+https://github.com/jonathanvanleeuwen/lib_auth.git@v1.1.0
```

## Usage

`lib_auth` provides authentication for FastAPI applications using **API keys** and/or **OAuth 2.0** (GitHub, Google).

### Quick Start: API Keys Only

**Step 1: Generate your API keys**

```python
from lib_auth.utils.auth_utils import hash_api_key

# Your raw API key (keep this secret!)
raw_key = "my-secret-api-key-12345"

# Hash it for storage
hashed_key = hash_api_key(raw_key)
print(hashed_key)
# Output: 'a1b2c3d4e5f6...' (SHA256 hash)

# Store this in your environment/config as a dict
api_keys = {
    hashed_key: {
        "username": "alice",
        "roles": ["admin", "user"]
    }
}
```

**Step 2: Protect your routes**

```python
from fastapi import Depends, FastAPI
from lib_auth.auth.authentication import create_auth

app = FastAPI()

@app.get(
    "/admin-only",
    dependencies=[
        Depends(
            create_auth(
                api_keys={
                    "a1b2c3d4e5f6...": {"username": "alice", "roles": ["admin"]},
                },
                oauth_secret_key="not-used-for-api-keys-only",
                allowed_roles=["admin"],
            )
        )
    ],
)
def admin_endpoint():
    return {"status": "admin only"}
```

**Step 3: Call your API**

```bash
curl -H "Authorization: Bearer my-secret-api-key-12345" http://localhost:8000/admin-only
```

---

### OAuth 2.0 Only (GitHub or Google)

**Step 1: Set up OAuth provider**

Get OAuth credentials:
- **GitHub**: [Create OAuth App](https://github.com/settings/developers) → New OAuth App
- **Google**: [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials

**Step 2: Add OAuth router and protect routes**

```python
from fastapi import Depends, FastAPI
from lib_auth.auth.authentication import create_auth
from lib_auth.routers.oauth import create_oauth_router

app = FastAPI()

# Add OAuth endpoints (/auth/oauth/provider, /auth/oauth/authorize, /auth/oauth/token)
app.include_router(
    create_oauth_router(
        oauth_provider="github",  # or "google"
        oauth_client_id="your-github-client-id",
        oauth_client_secret="your-github-client-secret",
        oauth_secret_key="your-jwt-signing-secret-key",
        oauth_access_token_expire_minutes=60,
    )
)

# Protect routes with OAuth authentication
@app.get(
    "/user-data",
    dependencies=[
        Depends(
            create_auth(
                api_keys={},  # Empty dict - no API keys
                oauth_secret_key="your-jwt-signing-secret-key",
                allowed_roles=["user"],
            )
        )
    ],
)
def user_endpoint():
    return {"status": "authenticated user"}
```

**Step 3: Users authenticate via OAuth flow**

1. Frontend calls `GET /auth/oauth/authorize?redirect_uri=...` to get authorization URL
2. User logs in with GitHub/Google
3. Frontend receives authorization code
4. Frontend calls `POST /auth/oauth/token` with the code to get JWT access token
5. Frontend uses the JWT token in `Authorization: Bearer <token>` header

---

### Combined: API Keys + OAuth

Use both authentication methods:

```python
from fastapi import Depends, FastAPI
from lib_auth.auth.authentication import create_auth
from lib_auth.routers.oauth import create_oauth_router
from lib_auth.utils.auth_utils import hash_api_key

app = FastAPI()

# Prepare API keys
api_keys = {
    hash_api_key("admin-key-12345"): {"username": "admin", "roles": ["admin", "user"]},
    hash_api_key("service-key-67890"): {"username": "service", "roles": ["user"]},
}

oauth_secret = "your-jwt-signing-secret-key"

# Add OAuth router
app.include_router(
    create_oauth_router(
        oauth_provider="github",
        oauth_client_id="your-client-id",
        oauth_client_secret="your-client-secret",
        oauth_secret_key=oauth_secret,
        oauth_access_token_expire_minutes=60,
    )
)

# Admin-only endpoint (accepts API keys OR OAuth tokens with admin role)
@app.get(
    "/admin",
    dependencies=[
        Depends(
            create_auth(
                api_keys=api_keys,
                oauth_secret_key=oauth_secret,
                allowed_roles=["admin"],
            )
        )
    ],
)
def admin_only():
    return {"message": "Admin access granted"}

# User endpoint (accepts API keys OR OAuth tokens with user role)
@app.get(
    "/dashboard",
    dependencies=[
        Depends(
            create_auth(
                api_keys=api_keys,
                oauth_secret_key=oauth_secret,
                allowed_roles=["user", "admin"],
            )
        )
    ],
)
def dashboard():
    return {"message": "Welcome to dashboard"}
```

Users can authenticate with either:
- `Authorization: Bearer admin-key-12345` (API key)
- `Authorization: Bearer eyJhbGciOiJIUzI1NiIs...` (OAuth JWT token)

---

### Accessing User Info in Route Handlers

Once authentication is configured, access user information in any route handler via `request.state.user_info`:

```python
from fastapi import Depends, Request

@app.get(
    "/whoami",
    dependencies=[
        Depends(
            create_auth(
                api_keys=api_keys,
                oauth_secret_key=oauth_secret,
                allowed_roles=None,  # Allow any authenticated user
            )
        )
    ],
)
def whoami(request: Request):
    # Access the full user info dict
    user_info = getattr(request.state, "user_info", {})

    # user_info structure:
    # {
    #     "sub": "alice" or "user@example.com",
    #     "auth_type": "api_key" or "oauth",
    #     "roles": ["admin", "user"],
    #     "provider": "github"  # only for OAuth
    # }
    return user_info
```

**Recommended Pattern: Extract specific fields safely**

```python
@app.post("/upload")
def upload_document(doc: UploadDocument, request: Request):
    # Get the username/email safely
    user_id = getattr(request.state, "user_info", {}).get("sub")

    # Get the user's roles
    user_roles = getattr(request.state, "user_info", {}).get("roles", [])

    # Check authentication method
    auth_type = getattr(request.state, "user_info", {}).get("auth_type")

    # Use user_id to associate data with the authenticated user
    save_document(doc, uploaded_by=user_id)

    return {"status": "uploaded", "user": user_id}

@app.get("/user-documents")
def get_user_documents(request: Request):
    user_id = getattr(request.state, "user_info", {}).get("sub")

    # Fetch only documents belonging to the authenticated user
    documents = db.query(Document).filter(Document.owner == user_id).all()

    return {"documents": documents}
```

**Why use `getattr()` with a default?**
- It safely handles edge cases where `user_info` might not exist
- Returns an empty dict by default, preventing `AttributeError`
- Makes code more robust and production-ready

**Available Fields in `user_info`:**
- `sub` (str): Username (API key auth) or email (OAuth auth) - use this as the unique user identifier
- `auth_type` (str): Either `"api_key"` or `"oauth"`
- `roles` (list[str]): User's roles (e.g., `["admin", "user"]`)
- `provider` (str, OAuth only): OAuth provider name (e.g., `"github"`, `"google"`)

---

### Logging

`lib_auth` uses Python's standard `logging` module to provide visibility into authentication events. Configure logging in your application to control what you see.

#### Log Levels

- **INFO**: Successful authentication events (logins)
- **DEBUG**: Detailed authentication flow (token operations, role resolution)
- **WARNING**: Failed authentication attempts
- **ERROR**: OAuth provider errors and token exchange failures

#### Example Logging Configuration

```python
import logging

# Basic console logging (development)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# For production - log only INFO and above (avoids verbose DEBUG logs)
logging.getLogger("lib_auth").setLevel(logging.INFO)

# For debugging authentication issues
logging.getLogger("lib_auth").setLevel(logging.DEBUG)

# Disable lib_auth logging completely
logging.getLogger("lib_auth").setLevel(logging.CRITICAL)
```

#### What Gets Logged

**Successful API Key Login (INFO):**
```
INFO - lib_auth.auth.authentication - API key authentication successful: user=alice roles=['admin', 'user']
```

**Successful OAuth Login (INFO):**
```
INFO - lib_auth.routers.oauth - OAuth login successful: provider=github user=alice@example.com roles=['user']
```

**Failed Authentication (WARNING):**
```
WARNING - lib_auth.auth.authentication - Authentication failed: invalid credentials
```

**OAuth Provider Error (ERROR):**
```
ERROR - lib_auth.workers.oauth_service - Failed to exchange code for token: provider=github error=...
```

**Debug Flow (DEBUG - only when DEBUG level enabled):**
```
DEBUG - lib_auth.auth.authentication - Attempting API key authentication
DEBUG - lib_auth.auth.authentication - API key not found in configured keys
DEBUG - lib_auth.auth.authentication - Attempting OAuth token authentication
DEBUG - lib_auth.auth.oauth_auth - Verified access token: user=alice@example.com provider=github
DEBUG - lib_auth.utils.auth_utils - Resolved roles for user=alice@example.com: ['user']
```

#### Avoiding Log Spam

The library is designed to minimize duplicate logs during normal operation:
- **One log per successful login**: Either API key OR OAuth, not both
- **Token verification**: Only logged at DEBUG level (not INFO)
- **Role resolution**: Only logged at DEBUG level
- **OAuth flow**: INFO level only for complete login, DEBUG for intermediate steps

For high-traffic applications, keep logging at INFO level to see successful authentications without overwhelming logs with per-request token verifications.

---

### Custom Role Resolution (Advanced)

By default, OAuth users get the `"user"` role. You can look up roles from a database:

```python
async def get_roles_from_database(user_email: str) -> list[str]:
    """Look up user roles in your database."""
    user = await db.users.find_one({"email": user_email})
    return user.get("roles", ["user"]) if user else ["user"]

# Pass it when creating the OAuth router
app.include_router(
    create_oauth_router(
        oauth_provider="github",
        oauth_client_id="your-client-id",
        oauth_client_secret="your-client-secret",
        oauth_secret_key="your-jwt-signing-secret-key",
        oauth_access_token_expire_minutes=60,
        user_role_resolver=get_roles_from_database,  # Custom role lookup
    )
)
```

The role resolver can be sync or async - the library handles both automatically.

---

### Custom OAuth Providers

`lib_auth` includes built-in support for:
- **GitHub** - `oauth_provider="github"`
- **Google** - `oauth_provider="google"`
- **Microsoft** - `oauth_provider="microsoft"`
- **GitLab** - `oauth_provider="gitlab"`
- **LinkedIn** - `oauth_provider="linkedin"`
- **Discord** - `oauth_provider="discord"`

You can add custom OAuth providers in two ways:

#### Option 1: Register Globally (For Reuse Across Multiple Routers)

```python
from lib_auth.auth.oauth_providers import register_oauth_provider

# Register once at app startup
register_oauth_provider(
    name="okta",
    authorization_url="https://dev-123456.okta.com/oauth2/v1/authorize",
    token_url="https://dev-123456.okta.com/oauth2/v1/token",
    userinfo_url="https://dev-123456.okta.com/oauth2/v1/userinfo",
    scope="openid email profile",
)

# Now use it like any built-in provider
app.include_router(
    create_oauth_router(
        oauth_provider="okta",
        oauth_client_id="your-okta-client-id",
        oauth_client_secret="your-okta-client-secret",
        oauth_secret_key="your-jwt-secret",
        oauth_access_token_expire_minutes=60,
    )
)
```

#### Option 2: Pass Config Directly (One-Off Custom Provider)

```python
app.include_router(
    create_oauth_router(
        oauth_provider="custom-sso",
        oauth_client_id="your-client-id",
        oauth_client_secret="your-client-secret",
        oauth_secret_key="your-jwt-secret",
        oauth_access_token_expire_minutes=60,
        oauth_provider_config={
            "authorization_url": "https://sso.company.com/oauth/authorize",
            "token_url": "https://sso.company.com/oauth/token",
            "userinfo_url": "https://sso.company.com/api/userinfo",
            "scope": "openid email profile",
        },
    )
)
```

**Finding OAuth Endpoints:**
- Check your provider's OAuth documentation (usually called "Developer Docs" or "API Docs")
- Look for: Authorization URL, Token URL, UserInfo URL, and required scopes
- Common examples:
  - **Auth0**: `https://YOUR_DOMAIN.auth0.com/authorize`, `/oauth/token`, `/userinfo`
  - **Keycloak**: `https://YOUR_DOMAIN/auth/realms/REALM/protocol/openid-connect/authorize`, `/token`, `/userinfo`
  - **Okta**: `https://YOUR_DOMAIN.okta.com/oauth2/v1/authorize`, `/v1/token`, `/v1/userinfo`

---

## Service-to-Service Authentication (Short-Lived JWT Tokens)

`lib_auth` provides enterprise-grade service-to-service authentication using short-lived JWT tokens from cloud identity providers. This is the **recommended approach** for microservices authentication, offering:

- ✅ **Short-lived tokens** (typically 10-60 minutes) - minimal security risk
- ✅ **No shared secrets between services** - tokens issued by trusted identity provider
- ✅ **Automatic key rotation** - identity provider manages cryptographic keys
- ✅ **Cloud-native integration** - uses Azure Entra ID, Google Cloud Identity, or GitHub Apps
- ✅ **Zero-trust security** - each service validates caller identity independently

### Supported Providers

| Provider | Best For | Token Lifetime | Setup Complexity |
|----------|----------|----------------|------------------|
| **Azure Entra ID** | Azure deployments, Microsoft 365 integration | 60-90 min | Medium |
| **Google Cloud** | GCP deployments, Google Workspace integration | 60 min | Low |
| **GitHub Apps** | GitHub-centric workflows, open-source projects | 10 min | Low |

### Service-to-Service Flow Overview

```
┌─────────────┐                                    ┌─────────────┐
│  Service A  │                                    │  Service B  │
│             │                                    │             │
│  1. Needs   │                                    │   Protects  │
│     to call │                                    │   /api/data │
│     Service │                                    │   endpoint  │
│     B       │                                    │             │
└──────┬──────┘                                    └──────▲──────┘
       │                                                  │
       │  2. Request token for Service B                 │
       │     from identity provider                      │
       │                                                  │
       ▼                                                  │
┌────────────────────────────────┐                       │
│   Identity Provider            │                       │
│  (Azure/Google/GitHub)         │                       │
│                                │                       │
│  - Verifies Service A identity │                       │
│  - Issues short-lived JWT      │                       │
│    with aud=Service B          │                       │
└────────────────┬───────────────┘                       │
                 │                                        │
                 │  3. Returns JWT token                 │
                 │     (expires in 10-60 min)            │
                 │                                        │
                 ▼                                        │
         ┌─────────────┐                                 │
         │ Service A   │                                 │
         │ has token   │                                 │
         └──────┬──────┘                                 │
                │                                         │
                │  4. Call Service B with JWT            │
                │     Authorization: Bearer <token>      │
                └────────────────────────────────────────┘
                                                          │
                        5. Service B verifies token      │
                           - Checks signature            │
                           - Checks expiration           │
                           - Checks audience             │
                           - Returns data                │
```

### Setup Guide by Provider

#### Azure Entra ID (Recommended for Azure Deployments)

**Prerequisites:**
- Azure subscription
- Two app registrations (one per service)

**Step 1: Register Service A (Caller) in Azure Portal**

1. Go to [Azure Portal](https://portal.azure.com) → Entra ID → App registrations
2. "New registration" → Name: `service-a` → Register
3. Note the **Application (client) ID** and **Directory (tenant) ID**
4. Go to "Certificates & secrets" → "New client secret" → Create → Copy the **secret value**

**Step 2: Register Service B (API) in Azure Portal**

1. "New registration" → Name: `service-b` → Register
2. Note the **Application (client) ID**
3. Go to "Expose an API" → "Add a scope"
   - Application ID URI: `api://service-b` (or custom)
   - Scope name: `access_as_user`
   - Who can consent: Admins and users
   - Save
4. Go to "App roles" (optional) → "Create app role"
   - Display name: `Service.Read`
   - Allowed member types: Applications
   - Value: `Service.Read`
   - Save

**Step 3: Grant Service A Permission to Call Service B**

1. Go to Service A app registration → "API permissions"
2. "Add a permission" → "My APIs" → Select "service-b"
3. Select the scopes/roles you created → "Add permissions"
4. "Grant admin consent" (requires admin)

**Step 4: Configure Service B (API - Receives Calls)**

```python
from fastapi import Depends, FastAPI, Request
from lib_auth.service_auth import create_service_auth
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType

app = FastAPI()

# Configure Azure service authentication
service_config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.AZURE,
    tenant_id="your-tenant-id",              # From Step 1
    client_id="service-b-client-id",         # Service B's client ID
    client_secret="service-b-client-secret", # Service B's secret
    allowed_audiences=["api://service-b"],   # Must match Application ID URI
)

# Protect endpoints - only services with valid tokens can access
@app.get(
    "/api/data",
    dependencies=[
        Depends(
            create_service_auth(
                config=service_config,
                allowed_services=["service-a"],  # Optional: restrict to specific services
            )
        )
    ],
)
async def get_data(request: Request):
    # Access caller information
    service_info = request.state.service_info

    return {
        "message": "Data retrieved successfully",
        "caller": service_info.service_name,
        "roles": service_info.roles,
    }
```

**Step 5: Configure Service A (Client - Makes Calls)**

```python
import httpx
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
from lib_auth.service_auth.utils import get_service_token

# Configure provider (use Service A's credentials)
config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.AZURE,
    tenant_id="your-tenant-id",
    client_id="service-a-client-id",         # Service A's client ID
    client_secret="service-a-client-secret", # Service A's secret
)

async def call_service_b():
    # Get token for Service B
    token = await get_service_token(
        config=config,
        target_audience="api://service-b",  # Service B's Application ID URI
        service_name="service-a",
    )

    # Call Service B with the token
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://service-b.example.com/api/data",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
        return response.json()
```

---

#### Google Cloud Identity (Recommended for GCP Deployments)

**Prerequisites:**
- Google Cloud project
- Service accounts for each service

**Step 1: Create Service Account for Service A (Caller)**

```bash
# In Google Cloud Console or using gcloud CLI
gcloud iam service-accounts create service-a \
    --display-name="Service A"

# Create and download key
gcloud iam service-accounts keys create service-a-key.json \
    --iam-account=service-a@PROJECT_ID.iam.gserviceaccount.com
```

**Step 2: Create Service Account for Service B (API)**

```bash
gcloud iam service-accounts create service-b \
    --display-name="Service B"

gcloud iam service-accounts keys create service-b-key.json \
    --iam-account=service-b@PROJECT_ID.iam.gserviceaccount.com
```

**Step 3: Configure Service B (API - Receives Calls)**

```python
from fastapi import Depends, FastAPI, Request
from lib_auth.service_auth import create_service_auth
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType

app = FastAPI()

# Load service account key
with open("service-b-key.json") as f:
    service_account_key = f.read()

# Configure Google service authentication
service_config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.GOOGLE,
    private_key=service_account_key,  # Full JSON key file content
    client_id="service-b@PROJECT_ID.iam.gserviceaccount.com",
    allowed_audiences=[
        "service-b@PROJECT_ID.iam.gserviceaccount.com",
        "https://service-b.example.com",  # Your service URL
    ],
)

@app.get(
    "/api/data",
    dependencies=[
        Depends(create_service_auth(config=service_config))
    ],
)
async def get_data(request: Request):
    service_info = request.state.service_info
    return {
        "message": "Data from Service B",
        "caller": service_info.service_name,
    }
```

**Step 4: Configure Service A (Client - Makes Calls)**

```python
import httpx
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
from lib_auth.service_auth.utils import get_service_token

# Load service account key
with open("service-a-key.json") as f:
    service_account_key = f.read()

config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.GOOGLE,
    private_key=service_account_key,
    client_id="service-a@PROJECT_ID.iam.gserviceaccount.com",
)

async def call_service_b():
    token = await get_service_token(
        config=config,
        target_audience="https://service-b.example.com",  # Service B's URL or SA email
        service_name="service-a",
    )

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://service-b.example.com/api/data",
            headers={"Authorization": f"Bearer {token}"},
        )
        return response.json()
```

**Google Cloud Security Best Practices:**
- Store service account keys in Secret Manager, not in code
- Use Workload Identity on GKE instead of service account keys when possible
- Rotate service account keys regularly

---

#### GitHub Apps (Best for GitHub-Integrated Services)

**Prerequisites:**
- GitHub organization or personal account
- GitHub App created

**Step 1: Create a GitHub App**

1. Go to GitHub → Settings → Developer settings → GitHub Apps → "New GitHub App"
2. **App name**: `my-service-auth`
3. **Webhook**: Uncheck "Active" (not needed for auth)
4. **Permissions**: None required (we're only using it for auth tokens)
5. Create app → Note the **App ID**
6. Generate a private key → Download the `.pem` file

**Step 2: Configure Service B (API - Receives Calls)**

```python
from fastapi import Depends, FastAPI, Request
from lib_auth.service_auth import create_service_auth
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType

app = FastAPI()

# Load GitHub App private key
with open("github-app.pem") as f:
    private_key = f.read()

service_config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.GITHUB,
    app_id="123456",  # Your GitHub App ID
    private_key=private_key,  # PEM format private key
    allowed_audiences=["github-app-123456", "service-b"],
)

@app.get(
    "/api/data",
    dependencies=[
        Depends(create_service_auth(config=service_config))
    ],
)
async def get_data(request: Request):
    service_info = request.state.service_info
    return {
        "message": "Data from Service B",
        "caller": service_info.service_name,
        "github_app_id": service_info.metadata.get("github_app_id"),
    }
```

**Step 3: Configure Service A (Client - Makes Calls)**

```python
import httpx
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
from lib_auth.service_auth.utils import get_service_token

with open("github-app.pem") as f:
    private_key = f.read()

config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.GITHUB,
    app_id="123456",
    private_key=private_key,
)

async def call_service_b():
    token = await get_service_token(
        config=config,
        target_audience="service-b",  # Target service identifier
        service_name="service-a",
    )

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://service-b.example.com/api/data",
            headers={"Authorization": f"Bearer {token}"},
        )
        return response.json()
```

**Note:** GitHub provider uses self-signed JWT tokens. In production, consider using Azure or Google for stronger verification via public key infrastructure.

---

### Full Service-to-Service Example (Bidirectional)

This example shows Service A calling Service B, and Service B calling back to Service A.

**Service A Configuration:**

```python
from fastapi import Depends, FastAPI, Request
import httpx
from lib_auth.service_auth import create_service_auth
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
from lib_auth.service_auth.utils import get_service_token

app = FastAPI()

# Configuration for calling Service B
outgoing_config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.AZURE,
    tenant_id="tenant-id",
    client_id="service-a-client-id",
    client_secret="service-a-secret",
)

# Configuration for receiving calls from Service B
incoming_config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.AZURE,
    tenant_id="tenant-id",
    client_id="service-a-client-id",
    client_secret="service-a-secret",
    allowed_audiences=["api://service-a"],
)

# Service A calls Service B
@app.post("/process")
async def process_data(data: dict):
    # Get token for Service B
    token = await get_service_token(
        config=outgoing_config,
        target_audience="api://service-b",
        service_name="service-a",
    )

    # Call Service B
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://service-b/api/analyze",
            json=data,
            headers={"Authorization": f"Bearer {token}"},
        )
        return response.json()

# Service A receives callbacks from Service B
@app.post(
    "/api/callback",
    dependencies=[
        Depends(create_service_auth(config=incoming_config))
    ],
)
async def receive_callback(result: dict, request: Request):
    service_info = request.state.service_info

    # Verify it's actually Service B calling us
    if service_info.service_name != "service-b":
        raise HTTPException(403, "Unauthorized service")

    return {"status": "callback received", "result": result}
```

**Service B Configuration:**

```python
from fastapi import Depends, FastAPI, Request
import httpx
from lib_auth.service_auth import create_service_auth
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType
from lib_auth.service_auth.utils import get_service_token

app = FastAPI()

# Configuration for receiving calls from Service A
incoming_config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.AZURE,
    tenant_id="tenant-id",
    client_id="service-b-client-id",
    client_secret="service-b-secret",
    allowed_audiences=["api://service-b"],
)

# Configuration for calling back to Service A
outgoing_config = ServiceAuthConfig(
    provider=ServiceAuthProviderType.AZURE,
    tenant_id="tenant-id",
    client_id="service-b-client-id",
    client_secret="service-b-secret",
)

# Service B receives calls from Service A
@app.post(
    "/api/analyze",
    dependencies=[
        Depends(create_service_auth(config=incoming_config))
    ],
)
async def analyze_data(data: dict, request: Request):
    service_info = request.state.service_info

    # Do some processing
    result = {"analyzed": True, "data": data}

    # Get token to call back to Service A
    token = await get_service_token(
        config=outgoing_config,
        target_audience="api://service-a",
        service_name="service-b",
    )

    # Call back to Service A
    async with httpx.AsyncClient() as client:
        await client.post(
            "https://service-a/api/callback",
            json=result,
            headers={"Authorization": f"Bearer {token}"},
        )

    return {"status": "analysis complete"}
```

---

### Environment Variables Pattern (Recommended)

Store provider configuration in environment variables for security:

**.env file:**
```bash
# Azure example
SERVICE_AUTH_PROVIDER=azure
SERVICE_AUTH_TENANT_ID=your-tenant-id
SERVICE_AUTH_CLIENT_ID=your-client-id
SERVICE_AUTH_CLIENT_SECRET=your-client-secret
SERVICE_AUTH_ALLOWED_AUDIENCES=api://your-service

# Google example
# SERVICE_AUTH_PROVIDER=google
# SERVICE_AUTH_PRIVATE_KEY={"type":"service_account",...}
# SERVICE_AUTH_CLIENT_ID=service@project.iam.gserviceaccount.com

# GitHub example
# SERVICE_AUTH_PROVIDER=github
# SERVICE_AUTH_APP_ID=123456
# SERVICE_AUTH_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...
```

**Application code:**

```python
import os
from lib_auth.service_auth.models import ServiceAuthConfig, ServiceAuthProviderType

def get_service_auth_config() -> ServiceAuthConfig:
    """Load service auth config from environment variables."""
    provider = ServiceAuthProviderType(os.environ["SERVICE_AUTH_PROVIDER"])

    config = ServiceAuthConfig(
        provider=provider,
        tenant_id=os.getenv("SERVICE_AUTH_TENANT_ID"),
        client_id=os.getenv("SERVICE_AUTH_CLIENT_ID"),
        client_secret=os.getenv("SERVICE_AUTH_CLIENT_SECRET"),
        private_key=os.getenv("SERVICE_AUTH_PRIVATE_KEY"),
        app_id=os.getenv("SERVICE_AUTH_APP_ID"),
        allowed_audiences=os.getenv("SERVICE_AUTH_ALLOWED_AUDIENCES", "").split(","),
    )

    return config

# Use in your app
service_config = get_service_auth_config()

@app.get(
    "/protected",
    dependencies=[Depends(create_service_auth(config=service_config))]
)
async def protected_endpoint():
    return {"message": "Authenticated"}
```

---

### Security Best Practices

1. **Use Short Token Lifetimes**
   - Azure: 60-90 minutes (default)
   - Google: 60 minutes (default)
   - GitHub: 10 minutes (recommended)
   - Tokens are cached automatically - no performance penalty

2. **Validate Audience (aud) Claim**
   - Always configure `allowed_audiences` to prevent token reuse
   - Each service should only accept tokens meant for it

3. **Restrict Allowed Services**
   ```python
   create_service_auth(
       config=service_config,
       allowed_services=["service-a", "service-b"],  # Whitelist callers
   )
   ```

4. **Use Roles for Fine-Grained Access**
   ```python
   create_service_auth(
       config=service_config,
       required_roles=["Service.Read", "Service.Write"],
   )
   ```

5. **Store Credentials Securely**
   - Use Azure Key Vault, Google Secret Manager, or GitHub Secrets
   - Never commit credentials to source control
   - Rotate secrets regularly

6. **Monitor Authentication Events**
   ```python
   import logging
   logging.getLogger("lib_auth.service_auth").setLevel(logging.INFO)
   ```

---

### Troubleshooting

**Error: "Token expired"**
- Tokens are short-lived by design
- Library automatically caches tokens and refreshes them
- Check system clock synchronization (NTP)

**Error: "Token signing key not found"**
- Azure/Google: Identity provider's public keys couldn't be retrieved
- Check network connectivity to identity provider
- Verify tenant ID / project ID is correct

**Error: "Service 'X' not authorized"**
- Check `allowed_services` configuration
- Verify service name matches between caller and receiver
- Azure: Check app permissions and admin consent

**Error: "Invalid token"**
- Verify `allowed_audiences` matches the token's `aud` claim
- Check that client ID and secrets are correct
- Azure: Ensure Application ID URI is correctly configured

**Enable Debug Logging:**
```python
import logging
logging.getLogger("lib_auth.service_auth").setLevel(logging.DEBUG)
```

---

## Contributing

For development setup, testing, and contribution guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see LICENSE file for details.

---

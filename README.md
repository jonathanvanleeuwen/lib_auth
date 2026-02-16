# lib_auth

FastAPI authentication library supporting API keys and OAuth 2.0 (GitHub, Google, Microsoft, GitLab, LinkedIn, Discord).

<!-- Pytest Coverage Comment:Begin -->
<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/README.md"><img alt="Coverage" src="https://img.shields.io/badge/Coverage-64%25-yellow.svg" /></a><details><summary>Coverage Report </summary><table><tr><th>File</th><th>Stmts</th><th>Miss</th><th>Cover</th><th>Missing</th></tr><tbody><tr><td colspan="5"><b>src/lib_auth</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/__init__.py">__init__.py</a></td><td>1</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/auth</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/__init__.py">__init__.py</a></td><td>0</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/authentication.py">authentication.py</a></td><td>46</td><td>2</td><td>96%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/authentication.py#L60">60</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/authentication.py#L94">94</a></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/oauth_auth.py">oauth_auth.py</a></td><td>19</td><td>1</td><td>95%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/oauth_auth.py#L30">30</a></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/oauth_providers.py">oauth_providers.py</a></td><td>3</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/secrets_b64.py">secrets_b64.py</a></td><td>34</td><td>34</td><td>0%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/auth/secrets_b64.py#L1-L52">1&ndash;52</a></td></tr><tr><td colspan="5"><b>src/lib_auth/models</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/models/__init__.py">__init__.py</a></td><td>0</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/models/oauth.py">oauth.py</a></td><td>9</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/routers</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/routers/oauth.py">oauth.py</a></td><td>28</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/utils</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/utils/auth_utils.py">auth_utils.py</a></td><td>16</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td colspan="5"><b>src/lib_auth/workers</b></td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/__init__.py">__init__.py</a></td><td>0</td><td>0</td><td>100%</td><td>&nbsp;</td></tr><tr><td>&nbsp; &nbsp;<a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py">oauth_service.py</a></td><td>54</td><td>38</td><td>30%</td><td><a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L16">16</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L44-L76">44&ndash;76</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L84-L127">84&ndash;127</a>, <a href="https://github.com/jonathanvanleeuwen/lib_auth/blob/main/src/lib_auth/workers/oauth_service.py#L134-L140">134&ndash;140</a></td></tr><tr><td><b>TOTAL</b></td><td><b>210</b></td><td><b>75</b></td><td><b>64%</b></td><td>&nbsp;</td></tr></tbody></table></details>
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

## Contributing

For development setup, testing, and contribution guidelines, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see LICENSE file for details.

---

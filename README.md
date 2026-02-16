# lib_auth
A Python library with modern CI/CD setup.

## Features
* Automated testing on PR using GitHub Actions
* Pre-commit hooks for code quality (ruff, isort, trailing whitespace, etc.)
* Semantic release using GitHub Actions
* Automatic code coverage report in README
* Automatic wheel build and GitHub Release publishing
* Modern Python packaging with pyproject.toml

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

*Notes*
Workflows trigger when a branch is merged into main!
To install, please follow all the instructions in this readme.
The workflows require a PAT set as secret (see further down for instructions)
See the notes on how to create semantic releases at the bottom of the README.

If you followed all the steps, whenever a PR is merged into `main`, the workflows are triggered and should:
* Run pre-commit checks (fail fast on code quality issues)
* Ensure that tests pass (before merge)
* Create a code coverage report and commit that to the bottom of the README
* Create a semantic release (if you follow the semantic release pattern) and automatically update the version number of your code
* Build a wheel and publish it as a GitHub Release asset


# Installation

## Option 1: Install from Private GitHub Release (Recommended)
Since this is a private repository, you need to authenticate with a GitHub Personal Access Token (PAT).

### Configure git credentials (more secure, recommended)
This method doesn't expose your token in command history:

```bash
# Store credentials in git (one-time setup)
git config --global credential.helper store

# Then install normally - git will prompt for credentials once
pip install "git+https://github.com/jonathanvanleeuwen/lib_auth.git@VERSION"
# When prompted: username = your GitHub username, password = your PAT
```

### Step 1: Create a Personal Access Token (one-time setup)

1. Go to [GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)](https://github.com/settings/tokens)
2. Click **"Generate new token (classic)"**
3. Give it a descriptive name (e.g., `lib_auth-install`)
4. Select the **`repo`** scope (required for private repositories)
5. Click **"Generate token"**
6. **Copy the token immediately** - you won't be able to see it again!

### Step 2: Install the package

```bash
# Replace YOUR_TOKEN with your actual token and VERSION with the desired version (e.g., v1.0.0)
pip install "git+https://YOUR_TOKEN@github.com/jonathanvanleeuwen/lib_auth.git@VERSION"

# Install the latest version (main branch):
pip install "git+https://YOUR_TOKEN@github.com/jonathanvanleeuwen/lib_auth.git"
```

### Using uv (faster alternative to pip)

```bash
uv pip install "git+https://YOUR_TOKEN@github.com/jonathanvanleeuwen/lib_auth.git@v1.0.0"
```

## Option 2: Install from Wheel File in Repository

The latest wheel files are also committed to the `dist/` directory in the repository. After cloning:

```bash
# Clone the repository first
git clone https://github.com/jonathanvanleeuwen/lib_auth.git

# Install the wheel file directly
pip install lib_auth/dist/lib_auth-1.0.0-py3-none-any.whl
```

> **Note:** Replace the version number with the actual version in the `dist/` directory.

## Option 3: Install from Source (Clone Repository)

```bash
# Clone the repository
git clone https://github.com/jonathanvanleeuwen/lib_auth.git
cd lib_auth

# Install using pip
pip install .

# Or install in editable/development mode with dev dependencies
pip install -e ".[dev]"
```

## Option 4: Add to requirements.txt or pyproject.toml

**In requirements.txt:**

```txt
lib_auth @ git+https://github.com/jonathanvanleeuwen/lib_auth.git@v1.0.0
```

**In pyproject.toml (for projects using PEP 621):**

```toml
[project]
dependencies = [
    "lib_auth @ git+https://github.com/jonathanvanleeuwen/lib_auth.git@v1.0.0",
]
```

## Building a Wheel File Locally

```bash
pip install build
python -m build --wheel
# The wheel will be created in the dist/ directory
```


# Development Setup

1. Create new virtual environment
   ```bash
   python -m venv .venv
   ```
2. Activate the environment and install library with dev dependencies
   ```bash
   pip install -e ".[dev]"
   ```
3. Install pre-commit hooks
   ```bash
   pip install pre-commit
   pre-commit install
   ```
4. Run pre-commit on all files to ensure everything is properly set up
   ```bash
   pre-commit run --all-files
   ```
5. Check proper install by running tests
   ```bash
   pytest
   ```


# GitHub Repository Setup

Complete these steps in order to enable the CI/CD pipeline.

## Step 1: Create the Release Token (PAT)

The workflow needs a Personal Access Token to push to the protected `main` branch.

### Create a Fine-Grained PAT (Recommended - More Secure)

1. Go to [GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens](https://github.com/settings/tokens?type=beta)
2. Click **"Generate new token"**
3. Configure the token:
   - **Token name:** `RELEASE_TOKEN_lib_auth` (or similar descriptive name)
   - **Expiration:** Choose an appropriate duration (recommend 90 days, set a reminder to rotate)
   - **Repository access:** Select "Only select repositories" → choose this repository
   - **Permissions:**
     - **Contents:** Read and write (for pushing commits and tags)
     - **Metadata:** Read-only (automatically selected)
4. Click **"Generate token"**
5. **Copy the token immediately** - you won't see it again!

### Alternative: Classic PAT (Simpler but Broader Access)

If fine-grained tokens don't work for your use case:

1. Go to [GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)](https://github.com/settings/tokens)
2. Click **"Generate new token (classic)"**
3. Configure:
   - **Note:** `RELEASE_TOKEN_lib_auth`
   - **Expiration:** Set an appropriate duration
   - **Scopes:** Select `repo` (full control of private repositories)
4. Click **"Generate token"** and copy it

## Step 2: Add the Token as a Repository Secret

1. Go to your repository on GitHub
2. Navigate to **Settings → Secrets and variables → Actions**
3. Click **"New repository secret"**
4. Configure:
   - **Name:** `RELEASE_TOKEN`
   - **Secret:** Paste your copied PAT
5. Click **"Add secret"**

## Step 3: Configure Branch Protection with Rulesets

GitHub Rulesets provide modern, flexible branch protection. The PAT allows the workflow to bypass these rules while humans must go through PRs.

1. Go to your repository → **Settings → Rules → Rulesets**
2. Click **"New ruleset"** → **"New branch ruleset"**
3. Configure the ruleset:
   - **Ruleset name:** `Protect main`
   - **Enforcement status:** Active
   - **Target branches:** Click "Add target" → "Include by pattern" → enter `main`

4. Enable these rules:
   - ✅ **Restrict deletions** - Prevent branch deletion
   - ✅ **Require a pull request before merging**
     - Required approvals: `1` (or more)
     - ✅ Dismiss stale pull request approvals when new commits are pushed
     - ✅ Require conversation resolution before merging
   - ✅ **Require status checks to pass**
     - ✅ Require branches to be up to date before merging
     - Add status checks: `test` (from python-app.yml), `lint` (from python-app.yml)
   - ✅ **Block force pushes**

5. Click **"Create"**

## Step 4: Restrict Allowed Actions (Optional but Recommended)

Limit which GitHub Actions can run to reduce supply chain attack risk:

1. Go to **Settings → Actions → General**
2. Under "Actions permissions", select **"Allow [owner], and select non-[owner], actions and reusable workflows"**
3. In "Allow specified actions and reusable workflows", add:
   ```
   actions/checkout@*,
   actions/setup-python@*,
   MishaKav/pytest-coverage-comment@*,
   softprops/action-gh-release@*,
   ```
4. Click **"Save"**

## Security Model

This setup provides security through multiple layers:

| Protection | What it prevents |
|------------|------------------|
| **CODEOWNERS** | Requires your approval for any workflow changes |
| **Required PRs** | No direct pushes to main (humans must use PRs) |
| **Required reviews** | At least one approval needed for every change |
| **Status checks** | Tests must pass before merge |
| **PAT as secret** | Token only accessible to workflows, not forks |
| **Action allowlist** | Only trusted actions can run |

**Why is the PAT safe?**
- The PAT is stored as a secret, never exposed in logs (GitHub auto-masks it)
- Forks cannot access repository secrets
- Any attempt to modify workflows to steal the PAT requires your explicit approval via CODEOWNERS
- The PAT can only push; it cannot change branch protection rules


# Semantic Release

https://python-semantic-release.readthedocs.io/en/latest/

The workflows are triggered when you merge into main!

When committing, use the following format for your commit message:

**Patch release** (1.0.0 → 1.0.1):
```
fix: your commit message
```

**Minor release** (1.0.0 → 1.1.0):
```
feat: your commit message
```

**Major/breaking release** (1.0.0 → 2.0.0):
```
feat: your commit message

BREAKING CHANGE: description of breaking change
```


# Coverage Report
<!-- Pytest Coverage Comment:Begin -->
<!-- Pytest Coverage Comment:End -->

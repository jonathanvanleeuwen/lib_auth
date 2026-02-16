OAUTH_PROVIDERS = {
    "github": {
        "authorization_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "user:email",
    },
    "google": {
        "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scope": "openid email profile",
    },
    "microsoft": {
        "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scope": "openid email profile",
    },
    "gitlab": {
        "authorization_url": "https://gitlab.com/oauth/authorize",
        "token_url": "https://gitlab.com/oauth/token",
        "userinfo_url": "https://gitlab.com/api/v4/user",
        "scope": "read_user",
    },
    "linkedin": {
        "authorization_url": "https://www.linkedin.com/oauth/v2/authorization",
        "token_url": "https://www.linkedin.com/oauth/v2/accessToken",
        "userinfo_url": "https://api.linkedin.com/v2/userinfo",
        "scope": "openid email profile",
    },
    "discord": {
        "authorization_url": "https://discord.com/api/oauth2/authorize",
        "token_url": "https://discord.com/api/oauth2/token",
        "userinfo_url": "https://discord.com/api/users/@me",
        "scope": "identify email",
    },
}


def register_oauth_provider(
    name: str,
    authorization_url: str,
    token_url: str,
    userinfo_url: str,
    scope: str,
) -> None:
    """Register a custom OAuth provider globally.

    Args:
        name: Provider name (e.g., "okta", "auth0")
        authorization_url: OAuth authorization endpoint
        token_url: OAuth token exchange endpoint
        userinfo_url: User info endpoint
        scope: OAuth scopes (space-separated)

    Example:
        register_oauth_provider(
            name="okta",
            authorization_url="https://dev-123456.okta.com/oauth2/v1/authorize",
            token_url="https://dev-123456.okta.com/oauth2/v1/token",
            userinfo_url="https://dev-123456.okta.com/oauth2/v1/userinfo",
            scope="openid email profile",
        )
    """
    OAUTH_PROVIDERS[name] = {
        "authorization_url": authorization_url,
        "token_url": token_url,
        "userinfo_url": userinfo_url,
        "scope": scope,
    }

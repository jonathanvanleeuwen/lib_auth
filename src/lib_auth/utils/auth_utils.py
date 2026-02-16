import hashlib


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def get_user_roles(user_email: str) -> list[str]:
    roles = ["user"]
    admin_domains = ["admin.com", "company.com"]
    admin_emails = ["admin@example.com"]

    if user_email in admin_emails or any(
        user_email.endswith(f"@{domain}") for domain in admin_domains
    ):
        roles.append("admin")

    return roles

# apps/dashboard/dashboard/config.py
import os

_VALID_ROLES = {"analyst", "admin"}


def _parse_dashboard_users(raw: str) -> dict[str, dict[str, str]]:
    """
    Parse DASHBOARD_USERS="user:werkzeug-hash:role,user2:werkzeug-hash".

    Werkzeug password hashes themselves contain colons (e.g.
    "scrypt:32768:8:1$salt$hash"), so the trailing segment is only treated
    as a role when it matches a known role name; otherwise the role
    defaults to "analyst" and the whole remainder is the hash.
    """
    users: dict[str, dict[str, str]] = {}
    for entry in filter(None, (e.strip() for e in raw.split(","))):
        parts = entry.split(":")
        if len(parts) < 2:
            continue
        username = parts[0]
        if len(parts) > 2 and parts[-1] in _VALID_ROLES:
            role = parts[-1]
            password_hash = ":".join(parts[1:-1])
        else:
            role = "analyst"
            password_hash = ":".join(parts[1:])
        users[username] = {"password_hash": password_hash, "role": role}
    return users


class Config:
    SECRET_KEY = os.environ.get("DASHBOARD_SECRET_KEY", "dev-secret-change-me")
    LDR_API_BASE = os.environ.get("LDR_API_BASE", "http://localhost:8000")
    # How long (seconds) requests to the backend API should wait before timing out
    API_TIMEOUT = int(os.environ.get("API_TIMEOUT", "10"))
    DASHBOARD_API_TOKEN = os.environ.get("DASHBOARD_API_TOKEN", "dev-dashboard-token")

    DASHBOARD_USERS = _parse_dashboard_users(os.environ.get("DASHBOARD_USERS", ""))

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Default False for local HTTP dev; set true behind HTTPS
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = int(
        os.environ.get("PERMANENT_SESSION_LIFETIME_SECONDS", str(8 * 3600))
    )

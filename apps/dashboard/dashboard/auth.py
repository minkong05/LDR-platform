# apps/dashboard/dashboard/auth.py
from __future__ import annotations

from functools import wraps

from flask import abort, current_app, flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash

# Endpoints reachable without a session: the login page itself, the Docker
# healthcheck, and static assets (css/js needed to render the login page).
PUBLIC_ENDPOINTS = {"auth.login", "main.health", "static"}


def verify_credentials(username: str, password: str) -> str | None:
    """Return the user's role if username/password are valid, else None."""
    user = current_app.config["DASHBOARD_USERS"].get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return None
    return user["role"]


def login_required():
    """
    Global before_request hook: redirect anonymous requests to /login
    unless the endpoint is public. Registered once in app.py via
    `app.before_request(login_required)`.
    """
    if request.endpoint is None or request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if "username" in session:
        return None
    return redirect(url_for("auth.login", next=request.path))


def role_required(*roles: str):
    """View decorator: require the session's role to be one of `roles`."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("auth.login", next=request.path))
            if session.get("role") not in roles:
                flash("You do not have permission to perform this action.", "danger")
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator

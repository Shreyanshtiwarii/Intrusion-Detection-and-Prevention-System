"""Decorators to protect routes and APIs behind an authenticated session."""

from functools import wraps
from flask import session, redirect, url_for, jsonify, request


def login_required(view_func):
    """Redirect unauthenticated browser requests to login; return 401 for APIs."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Authentication required"}), 401
            return redirect(url_for("auth.login_page"))
        return view_func(*args, **kwargs)

    return wrapped


def api_login_required(view_func):
    """Strict JSON-only guard for pure API endpoints."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"success": False, "error": "Authentication required"}), 401
        return view_func(*args, **kwargs)

    return wrapped

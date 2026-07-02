"""
Authentication service: credential verification, session lifecycle,
and login-history tracking.
"""

from datetime import datetime
from flask import session
from database import db
from models.user import User
from models.login_history import LoginHistory
from utils.logger import log_event


def attempt_login(username, password, ip_address, user_agent):
    """
    Validate credentials, record login history, and start a session on success.
    Returns (success: bool, message: str, user: User|None)
    """
    user = User.query.filter_by(username=username).first()
    success = bool(user and user.is_active and user.check_password(password))

    history = LoginHistory(
        username=username,
        ip_address=ip_address,
        success=success,
        user_agent=user_agent,
    )
    db.session.add(history)

    if success:
        user.last_login = datetime.utcnow()
        db.session.commit()

        session.clear()
        session.permanent = True
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role

        log_event(f"User '{username}' logged in from {ip_address}", level="INFO", source="auth")
        return True, "Login successful", user

    db.session.commit()
    log_event(f"Failed login attempt for '{username}' from {ip_address}", level="WARNING", source="auth")
    return False, "Invalid username or password", None


def logout_user_session():
    username = session.get("username", "unknown")
    session.clear()
    log_event(f"User '{username}' logged out", level="INFO", source="auth")


def current_user():
    if "user_id" not in session:
        return None
    return User.query.get(session["user_id"])


def is_authenticated():
    return "user_id" in session

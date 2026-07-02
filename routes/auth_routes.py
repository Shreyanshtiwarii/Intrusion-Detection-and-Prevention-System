from flask import Blueprint, render_template, request, redirect, url_for, jsonify, session

from authentication.auth import attempt_login, logout_user_session, is_authenticated
from authentication.decorators import login_required
from utils.validators import is_non_empty_string, success_response, error_response

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET"])
def index():
    if is_authenticated():
        return redirect(url_for("dashboard.dashboard_page"))
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/login", methods=["GET"])
def login_page():
    if is_authenticated():
        return redirect(url_for("dashboard.dashboard_page"))
    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user_session()
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not is_non_empty_string(username) or not is_non_empty_string(password):
        payload, status = error_response("Username and password are required")
        return jsonify(payload), status

    ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")

    success, message, user = attempt_login(username, password, ip_address, user_agent)

    if not success:
        payload, status = error_response(message, 401)
        return jsonify(payload), status

    payload, status = success_response({"user": user.to_dict()}, message)
    return jsonify(payload), status


@auth_bp.route("/api/auth/logout", methods=["POST"])
@login_required
def api_logout():
    logout_user_session()
    payload, status = success_response(message="Logged out successfully")
    return jsonify(payload), status


@auth_bp.route("/api/auth/session", methods=["GET"])
def api_session():
    if not is_authenticated():
        payload, status = error_response("Not authenticated", 401)
        return jsonify(payload), status
    payload, status = success_response({
        "username": session.get("username"),
        "role": session.get("role"),
    })
    return jsonify(payload), status

"""Input validation helpers used across route modules."""

import ipaddress
import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_username(value):
    return bool(value) and bool(USERNAME_RE.match(value))


def is_valid_port(value):
    try:
        port = int(value)
        return 0 <= port <= 65535
    except (ValueError, TypeError):
        return False


def is_non_empty_string(value, max_len=500):
    return isinstance(value, str) and 0 < len(value.strip()) <= max_len


def paginate_args(request_args, default_page=1, default_per_page=25, max_per_page=200):
    try:
        page = max(1, int(request_args.get("page", default_page)))
    except (ValueError, TypeError):
        page = default_page
    try:
        per_page = int(request_args.get("per_page", default_per_page))
        per_page = min(max(1, per_page), max_per_page)
    except (ValueError, TypeError):
        per_page = default_per_page
    return page, per_page


def error_response(message, status_code=400, details=None):
    payload = {"success": False, "error": message}
    if details:
        payload["details"] = details
    return payload, status_code


def success_response(data=None, message=None, status_code=200):
    payload = {"success": True}
    if message:
        payload["message"] = message
    if data is not None:
        payload["data"] = data
    return payload, status_code

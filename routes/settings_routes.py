from flask import Blueprint, render_template, request, jsonify

from models.setting import Setting
from authentication.decorators import login_required
from utils.helpers import get_setting, set_setting
from utils.validators import success_response, error_response
from utils.logger import log_event

settings_bp = Blueprint("settings", __name__)

_ALLOWED_KEYS = {
    "monitoring_enabled",
    "auto_block_enabled",
    "syn_flood_threshold",
    "udp_flood_threshold",
    "icmp_flood_threshold",
    "port_scan_threshold",
    "brute_force_threshold",
    "excessive_request_threshold",
    "block_duration_minutes",
    "notification_sound_enabled",
    "logging_level",
}

_BOOL_KEYS = {"monitoring_enabled", "auto_block_enabled", "notification_sound_enabled"}
_INT_KEYS = {
    "syn_flood_threshold", "udp_flood_threshold", "icmp_flood_threshold",
    "port_scan_threshold", "brute_force_threshold", "excessive_request_threshold",
    "block_duration_minutes",
}


@settings_bp.route("/settings", methods=["GET"])
@login_required
def settings_page():
    return render_template("settings.html")


@settings_bp.route("/api/settings", methods=["GET"])
@login_required
def get_all_settings():
    rows = Setting.query.all()
    data = {row.key: row.value for row in rows}
    payload, status = success_response(data)
    return jsonify(payload), status


@settings_bp.route("/api/settings", methods=["POST"])
@login_required
def update_settings():
    data = request.get_json(silent=True) or {}
    updated = {}

    for key, value in data.items():
        if key not in _ALLOWED_KEYS:
            continue
        if key in _BOOL_KEYS:
            value = str(bool(value)).lower()
        elif key in _INT_KEYS:
            try:
                value = str(int(value))
            except (ValueError, TypeError):
                payload, status = error_response(f"'{key}' must be an integer")
                return jsonify(payload), status
        set_setting(key, value)
        updated[key] = value

    if not updated:
        payload, status = error_response("No valid settings provided")
        return jsonify(payload), status

    log_event(f"Settings updated: {updated}", level="INFO", source="settings")
    payload, status = success_response(updated, "Settings updated successfully")
    return jsonify(payload), status

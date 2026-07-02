from flask import Blueprint, render_template, request, jsonify, current_app, session

from models.blocked_ip import BlockedIP
from authentication.decorators import login_required
from utils.validators import is_valid_ip, paginate_args, success_response, error_response

ips_bp = Blueprint("ips", __name__)


@ips_bp.route("/ips-management", methods=["GET"])
@login_required
def ips_management_page():
    return render_template("ips_management.html")


@ips_bp.route("/api/ips", methods=["GET"])
@login_required
def list_blocked_ips():
    page, per_page = paginate_args(request.args)
    active_only = request.args.get("active_only", "true").lower() == "true"

    query = BlockedIP.query
    if active_only:
        query = query.filter_by(is_active=True)
    query = query.order_by(BlockedIP.blocked_at.desc())

    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    payload, status = success_response({
        "items": [i.to_dict() for i in items],
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })
    return jsonify(payload), status


@ips_bp.route("/api/ips/block", methods=["POST"])
@login_required
def block_ip():
    data = request.get_json(silent=True) or {}
    ip_address = data.get("ip_address", "").strip()
    reason = data.get("reason", "Manual block by admin")
    block_type = data.get("block_type", "Temporary")
    duration_minutes = int(data.get("duration_minutes", 60))

    if not is_valid_ip(ip_address):
        payload, status = error_response("A valid IP address is required")
        return jsonify(payload), status

    if block_type not in ("Temporary", "Permanent"):
        payload, status = error_response("block_type must be 'Temporary' or 'Permanent'")
        return jsonify(payload), status

    ips_engine = current_app.extensions["cybershield"]["ips_engine"]
    ok, message = ips_engine.block_ip(
        ip_address, reason=reason, block_type=block_type,
        duration_minutes=duration_minutes, blocked_by=session.get("username", "admin"),
    )
    payload, status = (success_response(message=message) if ok else error_response(message))
    return jsonify(payload), status


@ips_bp.route("/api/ips/unblock", methods=["POST"])
@login_required
def unblock_ip():
    data = request.get_json(silent=True) or {}
    ip_address = data.get("ip_address", "").strip()

    if not is_valid_ip(ip_address):
        payload, status = error_response("A valid IP address is required")
        return jsonify(payload), status

    ips_engine = current_app.extensions["cybershield"]["ips_engine"]
    ok, message = ips_engine.unblock_ip(ip_address, unblocked_by=session.get("username", "admin"))
    payload, status = (success_response(message=message) if ok else error_response(message))
    return jsonify(payload), status


@ips_bp.route("/api/ips/whitelist", methods=["GET"])
@login_required
def get_whitelist():
    payload, status = success_response(current_app.config.get("WHITELIST_IPS", []))
    return jsonify(payload), status

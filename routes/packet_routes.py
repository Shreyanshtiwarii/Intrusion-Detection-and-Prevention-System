from flask import Blueprint, render_template, request, jsonify, current_app

from authentication.decorators import login_required
from models.packet_log import PacketLog
from utils.validators import paginate_args, success_response, error_response

packet_bp = Blueprint("packets", __name__)


@packet_bp.route("/packets", methods=["GET"])
@login_required
def packets_page():
    return render_template("packets.html")


@packet_bp.route("/api/packets", methods=["GET"])
@login_required
def list_packets():
    page, per_page = paginate_args(request.args)
    protocol = request.args.get("protocol")
    source_ip = request.args.get("source_ip")

    query = PacketLog.query
    if protocol:
        query = query.filter_by(protocol=protocol)
    if source_ip:
        query = query.filter(PacketLog.source_ip.like(f"%{source_ip}%"))

    query = query.order_by(PacketLog.timestamp.desc())
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    payload, status = success_response({
        "items": [p.to_dict() for p in items],
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })
    return jsonify(payload), status


@packet_bp.route("/api/packets/sniffer/start", methods=["POST"])
@login_required
def start_sniffer():
    sniffer = current_app.extensions["cybershield"]["sniffer"]
    ok, message = sniffer.start()
    payload, status = (success_response(message=message) if ok else error_response(message))
    return jsonify(payload), status


@packet_bp.route("/api/packets/sniffer/stop", methods=["POST"])
@login_required
def stop_sniffer():
    sniffer = current_app.extensions["cybershield"]["sniffer"]
    ok, message = sniffer.stop()
    payload, status = (success_response(message=message) if ok else error_response(message))
    return jsonify(payload), status


@packet_bp.route("/api/packets/sniffer/status", methods=["GET"])
@login_required
def sniffer_status():
    sniffer = current_app.extensions["cybershield"]["sniffer"]
    payload, status = success_response(sniffer.get_stats())
    return jsonify(payload), status

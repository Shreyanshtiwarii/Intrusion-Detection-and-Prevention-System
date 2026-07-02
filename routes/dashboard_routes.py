from flask import Blueprint, render_template, jsonify, current_app

from authentication.decorators import login_required
from models.alert import Alert
from models.blocked_ip import BlockedIP
from models.packet_log import PacketLog
from utils.validators import success_response

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard_page():
    return render_template("dashboard.html")


@dashboard_bp.route("/api/dashboard/summary", methods=["GET"])
@login_required
def dashboard_summary():
    sniffer = current_app.extensions["cybershield"]["sniffer"]
    ids_engine = current_app.extensions["cybershield"]["ids_engine"]
    ips_engine = current_app.extensions["cybershield"]["ips_engine"]
    system_monitor = current_app.extensions["cybershield"]["system_monitor"]

    total_alerts = Alert.query.count()
    total_blocked_active = BlockedIP.query.filter_by(is_active=True).count()
    total_packets_db = PacketLog.query.count()

    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()

    severity_breakdown = {}
    for sev in ("Low", "Medium", "High", "Critical"):
        severity_breakdown[sev] = Alert.query.filter_by(severity=sev).count()

    data = {
        "sniffer": sniffer.get_stats(),
        "ids": ids_engine.get_stats(),
        "ips": ips_engine.get_stats(),
        "system": system_monitor.get_snapshot(),
        "totals": {
            "total_alerts": total_alerts,
            "total_blocked_active": total_blocked_active,
            "total_packets_db": total_packets_db,
        },
        "severity_breakdown": severity_breakdown,
        "recent_alerts": [a.to_dict() for a in recent_alerts],
    }
    payload, status = success_response(data)
    return jsonify(payload), status


@dashboard_bp.route("/api/dashboard/toggle-monitoring", methods=["POST"])
@login_required
def toggle_monitoring():
    from utils.helpers import get_setting, set_setting
    current = get_setting("monitoring_enabled", True, bool)
    set_setting("monitoring_enabled", not current)
    payload, status = success_response({"monitoring_enabled": not current})
    return jsonify(payload), status

from flask import Blueprint, render_template, request, jsonify

from database import db
from authentication.decorators import login_required
from models.alert import Alert
from utils.validators import paginate_args, success_response, error_response

alert_bp = Blueprint("alerts", __name__)


@alert_bp.route("/alerts", methods=["GET"])
@login_required
def alerts_page():
    return render_template("alerts.html")


@alert_bp.route("/api/alerts", methods=["GET"])
@login_required
def list_alerts():
    page, per_page = paginate_args(request.args)
    severity = request.args.get("severity")
    attack_type = request.args.get("attack_type")
    source_ip = request.args.get("source_ip")
    resolved = request.args.get("resolved")

    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    if attack_type:
        query = query.filter_by(attack_type=attack_type)
    if source_ip:
        query = query.filter(Alert.source_ip.like(f"%{source_ip}%"))
    if resolved is not None and resolved != "":
        query = query.filter_by(resolved=(resolved.lower() == "true"))

    query = query.order_by(Alert.timestamp.desc())
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()

    payload, status = success_response({
        "items": [a.to_dict() for a in items],
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })
    return jsonify(payload), status


@alert_bp.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolve_alert(alert_id):
    alert = Alert.query.get(alert_id)
    if not alert:
        payload, status = error_response("Alert not found", 404)
        return jsonify(payload), status
    alert.resolved = True
    db.session.commit()
    payload, status = success_response(alert.to_dict(), "Alert marked as resolved")
    return jsonify(payload), status


@alert_bp.route("/api/alerts/<int:alert_id>", methods=["DELETE"])
@login_required
def delete_alert(alert_id):
    alert = Alert.query.get(alert_id)
    if not alert:
        payload, status = error_response("Alert not found", 404)
        return jsonify(payload), status
    db.session.delete(alert)
    db.session.commit()
    payload, status = success_response(message="Alert deleted")
    return jsonify(payload), status


@alert_bp.route("/api/alerts/stats/by-type", methods=["GET"])
@login_required
def alerts_by_type():
    from sqlalchemy import func
    rows = db.session.query(Alert.attack_type, func.count(Alert.id)).group_by(Alert.attack_type).all()
    payload, status = success_response({t: c for t, c in rows})
    return jsonify(payload), status

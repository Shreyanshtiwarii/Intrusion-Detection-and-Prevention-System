import csv
import io
import os
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, Response, current_app, send_file

from authentication.decorators import login_required
from models.system_log import SystemLog
from models.alert import Alert
from models.packet_log import PacketLog
from models.blocked_ip import BlockedIP
from utils.validators import paginate_args, success_response, error_response
from reports.pdf_export import generate_table_pdf

log_bp = Blueprint("logs", __name__)

_SOURCES = {
    "system": {"model": SystemLog, "order_col": "timestamp",
               "columns": ["id", "timestamp", "level", "source", "message"]},
    "alerts": {"model": Alert, "order_col": "timestamp",
               "columns": ["id", "timestamp", "attack_type", "source_ip", "severity",
                           "threat_score", "action_taken"]},
    "packets": {"model": PacketLog, "order_col": "timestamp",
                "columns": ["id", "timestamp", "source_ip", "destination_ip", "protocol",
                            "source_port", "destination_port", "packet_size"]},
    "blocked_ips": {"model": BlockedIP, "order_col": "blocked_at",
                     "columns": ["id", "ip_address", "reason", "block_type", "blocked_at", "is_active"]},
}


@log_bp.route("/logs", methods=["GET"])
@login_required
def logs_page():
    return render_template("logs.html")


@log_bp.route("/api/logs/<source>", methods=["GET"])
@login_required
def list_logs(source):
    config = _SOURCES.get(source)
    if not config:
        payload, status = error_response("Unknown log source")
        return jsonify(payload), status

    page, per_page = paginate_args(request.args)
    search = request.args.get("search", "").strip()
    model = config["model"]

    query = model.query
    if search:
        like_clauses = []
        for col in config["columns"]:
            if col == "id":
                continue
            attr = getattr(model, col, None)
            if attr is not None and hasattr(attr.type, "python_type"):
                try:
                    if attr.type.python_type is str:
                        like_clauses.append(attr.like(f"%{search}%"))
                except NotImplementedError:
                    continue
        if like_clauses:
            from sqlalchemy import or_
            query = query.filter(or_(*like_clauses))

    order_col = getattr(model, config["order_col"])
    query = query.order_by(order_col.desc())

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


@log_bp.route("/api/logs/<source>/export/csv", methods=["GET"])
@login_required
def export_csv(source):
    config = _SOURCES.get(source)
    if not config:
        payload, status = error_response("Unknown log source")
        return jsonify(payload), status

    model = config["model"]
    order_col = getattr(model, config["order_col"])
    items = model.query.order_by(order_col.desc()).limit(10000).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(config["columns"])
    for item in items:
        row_dict = item.to_dict()
        writer.writerow([row_dict.get(col, "") for col in config["columns"]])

    response = Response(buffer.getvalue(), mimetype="text/csv")
    filename = f"cybershield_{source}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


@log_bp.route("/api/logs/<source>/export/pdf", methods=["GET"])
@login_required
def export_pdf(source):
    config = _SOURCES.get(source)
    if not config:
        payload, status = error_response("Unknown log source")
        return jsonify(payload), status

    model = config["model"]
    order_col = getattr(model, config["order_col"])
    items = model.query.order_by(order_col.desc()).limit(2000).all()

    headers = config["columns"]
    rows = []
    for item in items:
        row_dict = item.to_dict()
        rows.append([str(row_dict.get(col, "")) for col in headers])

    filename = f"cybershield_{source}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(current_app.config["REPORTS_DIR"], filename)
    generate_table_pdf(f"CyberShield - {source.replace('_', ' ').title()} Export", headers, rows, output_path)

    return send_file(output_path, as_attachment=True, download_name=filename)

import os
from datetime import datetime

from flask import Blueprint, render_template, request, jsonify, current_app, send_file

from database import db
from models.report import Report
from authentication.decorators import login_required
from reports.generator import build_report_data
from reports.pdf_export import generate_report_pdf
from utils.validators import success_response, error_response
from utils.logger import log_event

report_bp = Blueprint("reports", __name__)


@report_bp.route("/reports", methods=["GET"])
@login_required
def reports_page():
    return render_template("reports.html")


@report_bp.route("/api/reports", methods=["GET"])
@login_required
def list_reports():
    items = Report.query.order_by(Report.generated_at.desc()).limit(100).all()
    payload, status = success_response([i.to_dict() for i in items])
    return jsonify(payload), status


@report_bp.route("/api/reports/generate", methods=["POST"])
@login_required
def generate_report():
    data = request.get_json(silent=True) or {}
    report_type = data.get("report_type", "Daily")

    if report_type not in ("Daily", "Weekly", "Monthly"):
        payload, status = error_response("report_type must be Daily, Weekly, or Monthly")
        return jsonify(payload), status

    report_data = build_report_data(report_type)

    filename = f"cybershield_{report_type.lower()}_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(current_app.config["REPORTS_DIR"], filename)
    generate_report_pdf(report_data, output_path)

    report = Report(
        report_type=report_type,
        period_start=report_data["period_start"],
        period_end=report_data["period_end"],
        total_alerts=report_data["total_alerts"],
        total_blocked=report_data["total_blocked"],
        total_packets=report_data["total_packets"],
        file_path=output_path,
    )
    db.session.add(report)
    db.session.commit()

    log_event(f"{report_type} report generated ({report.total_alerts} alerts)", level="INFO", source="reports")

    payload, status = success_response(report.to_dict(), f"{report_type} report generated")
    return jsonify(payload), status


@report_bp.route("/api/reports/<int:report_id>/download", methods=["GET"])
@login_required
def download_report(report_id):
    report = Report.query.get(report_id)
    if not report or not report.file_path or not os.path.isfile(report.file_path):
        payload, status = error_response("Report file not found", 404)
        return jsonify(payload), status
    return send_file(report.file_path, as_attachment=True,
                      download_name=os.path.basename(report.file_path))

from flask import Blueprint, render_template, request, jsonify, current_app

from models.file_hash import FileHash
from authentication.decorators import login_required
from utils.validators import success_response, error_response

fim_bp = Blueprint("fim", __name__)


@fim_bp.route("/file-integrity", methods=["GET"])
@login_required
def fim_page():
    return render_template("file_integrity.html")


@fim_bp.route("/api/fim/files", methods=["GET"])
@login_required
def list_watched_files():
    items = FileHash.query.order_by(FileHash.last_checked.desc()).all()
    payload, status = success_response([i.to_dict() for i in items])
    return jsonify(payload), status


@fim_bp.route("/api/fim/add", methods=["POST"])
@login_required
def add_watch_file():
    import os
    data = request.get_json(silent=True) or {}
    path = data.get("file_path", "").strip()

    if not path or not os.path.isfile(path):
        payload, status = error_response("A valid, existing file path is required")
        return jsonify(payload), status

    fim = current_app.extensions["cybershield"]["fim"]
    fim.add_watch_path(path)

    with current_app.app_context():
        fim.scan_once()

    payload, status = success_response(message=f"Now monitoring {path}")
    return jsonify(payload), status


@fim_bp.route("/api/fim/remove", methods=["POST"])
@login_required
def remove_watch_file():
    from database import db
    data = request.get_json(silent=True) or {}
    path = data.get("file_path", "").strip()

    fim = current_app.extensions["cybershield"]["fim"]
    fim.remove_watch_path(path)

    record = FileHash.query.filter_by(file_path=path).first()
    if record:
        db.session.delete(record)
        db.session.commit()

    payload, status = success_response(message=f"Stopped monitoring {path}")
    return jsonify(payload), status


@fim_bp.route("/api/fim/scan-now", methods=["POST"])
@login_required
def scan_now():
    fim = current_app.extensions["cybershield"]["fim"]
    with current_app.app_context():
        fim.scan_once()
    payload, status = success_response(message="Scan complete")
    return jsonify(payload), status

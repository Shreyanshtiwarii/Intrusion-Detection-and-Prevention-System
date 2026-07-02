"""
CyberShield IDS/IPS -- AI Assisted Real-Time Intrusion Detection & Prevention System

Application entry point. Boots Flask + SocketIO, initializes the database,
wires together the packet sniffer, IDS engine, IPS engine, system monitor,
and file-integrity monitor, then starts serving.

Run with:  python app.py
(Packet capture requires elevated privileges: sudo python app.py on Linux/macOS,
 or an Administrator terminal on Windows.)
"""

import os
import threading
import time

from flask import Flask, request, jsonify, session
from flask_socketio import SocketIO

import schedule

from config import get_config
from database import db, init_db
from routes import register_blueprints

from utils.logger import init_logger, register_socketio, log_event
from utils.validators import error_response

from packet_capture.sniffer import PacketSniffer
from ids_engine.detector import IDSEngine
from ips_engine.blocker import IPSEngine
from monitoring.system_monitor import SystemMonitor
from monitoring.file_integrity import FileIntegrityMonitor


def create_app():
    app = Flask(__name__)
    app.config.from_object(get_config())

    init_logger(app)
    init_db(app)

    socketio = SocketIO(app, async_mode=app.config["SOCKETIO_ASYNC_MODE"], cors_allowed_origins="*")
    register_socketio(socketio)

    # ------------------------------------------------------------------
    # Wire up engines. IDS needs a *lazy* reference to the IPS engine to
    # avoid a circular construction dependency, hence the getter closure.
    # ------------------------------------------------------------------
    app.extensions["cybershield"] = {}
    ips_engine = IPSEngine(app, socketio)
    ids_engine = IDSEngine(app, socketio, ips_engine_getter=lambda: ips_engine)
    sniffer = PacketSniffer(
        app, socketio, ids_engine,
        interface=app.config["CAPTURE_INTERFACE"],
        bpf_filter=app.config["CAPTURE_BPF_FILTER"],
    )
    system_monitor = SystemMonitor(app, socketio, interval_seconds=3)
    fim = FileIntegrityMonitor(
        app, socketio,
        watch_paths=list(app.config["FIM_WATCH_PATHS"]),
        interval_seconds=app.config["FIM_SCAN_INTERVAL_SECONDS"],
    )

    app.extensions["cybershield"].update({
        "socketio": socketio,
        "sniffer": sniffer,
        "ids_engine": ids_engine,
        "ips_engine": ips_engine,
        "system_monitor": system_monitor,
        "fim": fim,
    })

    register_blueprints(app)

    # ------------------------------------------------------------------
    # Request-level IPS enforcement + IDS web-layer detection
    # ------------------------------------------------------------------
    @app.before_request
    def enforce_ips_and_detect():
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

        if request.path.startswith("/static/"):
            return None

        if ips_engine.is_blocked(client_ip) and not ips_engine.is_whitelisted(client_ip):
            log_event(f"Blocked IP {client_ip} attempted access to {request.path}",
                       level="WARNING", source="ips_engine")
            payload, status = error_response("Access denied: your IP address has been blocked", 403)
            return jsonify(payload), status

        if request.path.startswith("/api/") and request.path != "/api/auth/login":
            ids_engine.process_http_request(
                client_ip,
                user_agent=request.headers.get("User-Agent", ""),
                path=request.path,
            )

        return None

    @app.after_request
    def detect_brute_force(response):
        try:
            if request.path == "/api/auth/login" and request.method == "POST" and response.status_code == 401:
                client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
                ids_engine.process_failed_login(client_ip)
        except Exception as exc:  # noqa: BLE001
            log_event(f"Brute-force hook error: {exc}", level="ERROR", source="ids_engine")
        return response

    # ------------------------------------------------------------------
    # Error handlers
    # ------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            payload, status = error_response("Resource not found", 404)
            return jsonify(payload), status
        from flask import render_template
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        log_event(f"Unhandled server error: {e}", level="ERROR", source="app")
        if request.path.startswith("/api/"):
            payload, status = error_response("Internal server error", 500)
            return jsonify(payload), status
        return "Internal Server Error", 500

    # ------------------------------------------------------------------
    # SocketIO events
    # ------------------------------------------------------------------
    @socketio.on("connect")
    def handle_connect():
        if "user_id" not in session:
            return False  # reject unauthenticated socket connections
        log_event(f"Dashboard client connected: {session.get('username')}", level="INFO",
                   source="socketio", persist=False, broadcast=False)

    @socketio.on("disconnect")
    def handle_disconnect():
        pass

    return app, socketio, {
        "ips_engine": ips_engine,
        "ids_engine": ids_engine,
        "sniffer": sniffer,
        "system_monitor": system_monitor,
        "fim": fim,
    }


def start_background_services(app, engines):
    """Start long-running background threads: system monitor, FIM, sniffer,
    and the periodic scheduler (block expiry sweep)."""
    engines["system_monitor"].start()
    engines["fim"].start()

    auto_start_capture = os.environ.get("AUTO_START_CAPTURE", "true").lower() == "true"
    if auto_start_capture:
        ok, message = engines["sniffer"].start()
        if not ok:
            log_event(f"Auto-start capture skipped: {message}", level="WARNING", source="app")

    def run_scheduler():
        schedule.every(1).minutes.do(engines["ips_engine"].expire_stale_blocks)
        while True:
            schedule.run_pending()
            time.sleep(5)

    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

    log_event("CyberShield background services started", level="INFO", source="app")


app, socketio, engines = create_app()

with app.app_context():
    start_background_services(app, engines)


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'=' * 60}")
    print("  CyberShield IDS/IPS -- Starting Server")
    print(f"  URL:      http://localhost:{port}")
    print(f"  Login:    {app.config['DEFAULT_ADMIN_USERNAME']} / {app.config['DEFAULT_ADMIN_PASSWORD']}")
    print(f"{'=' * 60}\n")
    socketio.run(app, host=host, port=port, debug=app.config["DEBUG"], use_reloader=False,
                 allow_unsafe_werkzeug=True)

"""
CyberShield IDS/IPS - Database Bootstrap
Central SQLAlchemy instance shared by every model/module (avoids circular imports).
"""

import os
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Attach SQLAlchemy to the Flask app, create tables, and seed defaults."""
    db_dir = os.path.dirname(app.config["DB_PATH"])
    os.makedirs(db_dir, exist_ok=True)
    os.makedirs(app.config["LOGS_DIR"], exist_ok=True)
    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    db.init_app(app)

    with app.app_context():
        # Import models here so they register with SQLAlchemy metadata
        from models.user import User
        from models.alert import Alert
        from models.blocked_ip import BlockedIP
        from models.packet_log import PacketLog
        from models.system_log import SystemLog
        from models.report import Report
        from models.setting import Setting
        from models.login_history import LoginHistory
        from models.file_hash import FileHash

        db.create_all()
        _seed_defaults(app)


def _seed_defaults(app):
    from models.user import User
    from models.setting import Setting

    if User.query.count() == 0:
        admin = User(username=app.config["DEFAULT_ADMIN_USERNAME"])
        admin.set_password(app.config["DEFAULT_ADMIN_PASSWORD"])
        db.session.add(admin)

    if Setting.query.count() == 0:
        defaults = {
            "monitoring_enabled": "true",
            "auto_block_enabled": str(app.config["AUTO_BLOCK_ENABLED_DEFAULT"]).lower(),
            "syn_flood_threshold": str(app.config["SYN_FLOOD_THRESHOLD"]),
            "udp_flood_threshold": str(app.config["UDP_FLOOD_THRESHOLD"]),
            "icmp_flood_threshold": str(app.config["ICMP_FLOOD_THRESHOLD"]),
            "port_scan_threshold": str(app.config["PORT_SCAN_THRESHOLD"]),
            "brute_force_threshold": str(app.config["BRUTE_FORCE_THRESHOLD"]),
            "excessive_request_threshold": str(app.config["EXCESSIVE_REQUEST_THRESHOLD"]),
            "block_duration_minutes": str(app.config["DEFAULT_BLOCK_DURATION_MINUTES"]),
            "notification_sound_enabled": "true",
            "logging_level": app.config["LOG_LEVEL"],
        }
        for key, value in defaults.items():
            db.session.add(Setting(key=key, value=value))

    db.session.commit()

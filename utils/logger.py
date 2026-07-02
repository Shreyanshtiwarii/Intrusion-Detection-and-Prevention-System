"""
Centralized logging utility.
Writes structured log entries to: (1) rotating log file, (2) SystemLog DB table,
and (3) broadcasts to connected dashboards via SocketIO if available.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

_file_logger = None
_socketio_ref = None


def init_logger(app):
    """Configure the rotating file logger. Call once at app startup."""
    global _file_logger
    os.makedirs(app.config["LOGS_DIR"], exist_ok=True)
    log_path = os.path.join(app.config["LOGS_DIR"], "cybershield.log")

    logger = logging.getLogger("cybershield")
    logger.setLevel(getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO))

    if not logger.handlers:
        handler = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)

    _file_logger = logger
    return logger


def register_socketio(socketio):
    global _socketio_ref
    _socketio_ref = socketio


def log_event(message, level="INFO", source="system", persist=True, broadcast=True):
    """
    Log an event across all sinks.
    level: INFO / WARNING / ERROR / CRITICAL
    source: module name that generated the event
    """
    global _file_logger

    if _file_logger:
        log_fn = {
            "INFO": _file_logger.info,
            "WARNING": _file_logger.warning,
            "ERROR": _file_logger.error,
            "CRITICAL": _file_logger.critical,
        }.get(level.upper(), _file_logger.info)
        log_fn(f"[{source}] {message}")
    else:
        print(f"[{level}] [{source}] {message}")

    if persist:
        try:
            from database import db
            from models.system_log import SystemLog
            entry = SystemLog(level=level.upper(), source=source, message=message)
            db.session.add(entry)
            db.session.commit()
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to persist system log: {exc}")

    if broadcast and _socketio_ref:
        try:
            _socketio_ref.emit("system_log", {
                "level": level.upper(),
                "source": source,
                "message": message,
            })
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to broadcast system log: {exc}")

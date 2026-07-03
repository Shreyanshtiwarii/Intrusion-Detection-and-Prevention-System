"""
CyberShield IDS/IPS - Application Configuration
Loads configuration from environment variables with sane production defaults.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration shared across environments."""

    # --- Core Flask ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "cybershield-dev-secret-change-in-production")
    DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

    # --- Database ---
    DB_PATH = os.path.join(BASE_DIR, "database", "cybershield.db")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}

    # --- Session ---
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.environ.get("SESSION_HOURS", 8)))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # --- Default Admin Credentials (used only on first-run seed) ---
    DEFAULT_ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123")

    # --- Packet Capture ---
    CAPTURE_INTERFACE = os.environ.get("CAPTURE_INTERFACE", None)  # None = auto/default iface
    CAPTURE_BPF_FILTER = os.environ.get("CAPTURE_BPF_FILTER", "")
    MAX_PACKET_LOG_RETENTION = int(os.environ.get("MAX_PACKET_LOG_RETENTION", 50000))

    # --- IDS Thresholds (overridable at runtime via Settings table) ---
    SYN_FLOOD_THRESHOLD = int(os.environ.get("SYN_FLOOD_THRESHOLD", 100))       # SYNs / window
    UDP_FLOOD_THRESHOLD = int(os.environ.get("UDP_FLOOD_THRESHOLD", 150))
    ICMP_FLOOD_THRESHOLD = int(os.environ.get("ICMP_FLOOD_THRESHOLD", 100))
    PORT_SCAN_THRESHOLD = int(os.environ.get("PORT_SCAN_THRESHOLD", 15))        # distinct ports
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD", 5))     # failed logins
    DETECTION_WINDOW_SECONDS = int(os.environ.get("DETECTION_WINDOW_SECONDS", 10))
    EXCESSIVE_REQUEST_THRESHOLD = int(os.environ.get("EXCESSIVE_REQUEST_THRESHOLD", 200))

    # --- IPS ---
    AUTO_BLOCK_ENABLED_DEFAULT = os.environ.get("AUTO_BLOCK_ENABLED_DEFAULT", "True").lower() == "true"
    DEFAULT_BLOCK_DURATION_MINUTES = int(os.environ.get("DEFAULT_BLOCK_DURATION_MINUTES", 60))
    WHITELIST_IPS = [ip.strip() for ip in os.environ.get("WHITELIST_IPS", "127.0.0.1").split(",") if ip.strip()]

    # --- File Integrity Monitoring ---
    FIM_WATCH_PATHS = [p.strip() for p in os.environ.get(
        "FIM_WATCH_PATHS",
        os.path.join(BASE_DIR, "config.py") + "," + os.path.join(BASE_DIR, "app.py")
    ).split(",") if p.strip()]
    FIM_SCAN_INTERVAL_SECONDS = int(os.environ.get("FIM_SCAN_INTERVAL_SECONDS", 30))

    # --- Reports / Logs ---
    LOGS_DIR = os.path.join(BASE_DIR, "logs")
    REPORTS_DIR = os.path.join(BASE_DIR, "logs", "reports")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

    # --- SocketIO ---
    SOCKETIO_ASYNC_MODE = os.environ.get("SOCKETIO_ASYNC_MODE", "eventlet")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "default")
    return config_map.get(env, DevelopmentConfig)

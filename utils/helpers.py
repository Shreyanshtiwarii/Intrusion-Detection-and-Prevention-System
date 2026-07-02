"""Misc helper functions shared across modules."""

import hashlib
from datetime import datetime, timedelta


def sha256_of_file(path, chunk_size=65536):
    """Compute the SHA-256 digest of a file on disk."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def now_utc():
    return datetime.utcnow()


def minutes_from_now(minutes):
    return datetime.utcnow() + timedelta(minutes=minutes)


def human_bytes(num):
    """Convert a byte count into a human readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"


def severity_from_score(score):
    """Map a 0-100 threat score to a severity label."""
    if score >= 85:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def get_setting(key, default=None, cast=str):
    """Read a runtime setting from the Settings table with a fallback default."""
    from models.setting import Setting
    row = Setting.query.filter_by(key=key).first()
    if row is None:
        return default
    try:
        if cast is bool:
            return row.value.lower() == "true"
        return cast(row.value)
    except (ValueError, TypeError):
        return default


def set_setting(key, value):
    from database import db
    from models.setting import Setting
    row = Setting.query.filter_by(key=key).first()
    if row is None:
        row = Setting(key=key, value=str(value))
        db.session.add(row)
    else:
        row.value = str(value)
    db.session.commit()
    return row

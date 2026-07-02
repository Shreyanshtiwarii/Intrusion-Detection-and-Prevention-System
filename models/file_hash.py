from datetime import datetime
from database import db


class FileHash(db.Model):
    __tablename__ = "file_hashes"

    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(500), unique=True, nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    last_modified_alert = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(16), default="OK")  # OK / MODIFIED / MISSING

    def to_dict(self):
        return {
            "id": self.id,
            "file_path": self.file_path,
            "sha256_hash": self.sha256_hash,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "last_modified_alert": self.last_modified_alert.isoformat() if self.last_modified_alert else None,
            "status": self.status,
        }

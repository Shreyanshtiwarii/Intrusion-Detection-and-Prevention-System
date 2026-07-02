from datetime import datetime
from database import db


class SystemLog(db.Model):
    __tablename__ = "system_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    level = db.Column(db.String(16), default="INFO", index=True)  # INFO/WARNING/ERROR/CRITICAL
    source = db.Column(db.String(64), nullable=True)  # module that generated the log
    message = db.Column(db.Text, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level,
            "source": self.source,
            "message": self.message,
        }

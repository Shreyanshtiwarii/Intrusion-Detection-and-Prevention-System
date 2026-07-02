from datetime import datetime
from database import db


class LoginHistory(db.Model):
    __tablename__ = "login_history"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=False)
    user_agent = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "success": self.success,
            "user_agent": self.user_agent,
        }

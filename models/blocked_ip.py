from datetime import datetime
from database import db


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    block_type = db.Column(db.String(16), default="Temporary")  # Temporary / Permanent
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # null => permanent
    is_active = db.Column(db.Boolean, default=True)
    blocked_by = db.Column(db.String(64), default="IPS Engine")  # IPS Engine / username
    unblocked_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "block_type": self.block_type,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "blocked_by": self.blocked_by,
            "unblocked_at": self.unblocked_at.isoformat() if self.unblocked_at else None,
        }

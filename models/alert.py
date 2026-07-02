from datetime import datetime
from database import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    attack_type = db.Column(db.String(64), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(16), nullable=True)
    severity = db.Column(db.String(16), nullable=False, default="Medium")  # Low/Medium/High/Critical
    threat_score = db.Column(db.Integer, nullable=False, default=0)        # 0-100
    confidence = db.Column(db.Integer, nullable=False, default=0)          # 0-100
    description = db.Column(db.Text, nullable=True)
    mitigation = db.Column(db.Text, nullable=True)
    raw_payload_snippet = db.Column(db.Text, nullable=True)
    action_taken = db.Column(db.String(64), default="Logged")  # Logged / Blocked / Ignored
    resolved = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "attack_type": self.attack_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "severity": self.severity,
            "threat_score": self.threat_score,
            "confidence": self.confidence,
            "description": self.description,
            "mitigation": self.mitigation,
            "raw_payload_snippet": self.raw_payload_snippet,
            "action_taken": self.action_taken,
            "resolved": self.resolved,
        }

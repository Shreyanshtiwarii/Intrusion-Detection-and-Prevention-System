from datetime import datetime
from database import db


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_type = db.Column(db.String(16), nullable=False)  # Daily / Weekly / Monthly
    period_start = db.Column(db.DateTime, nullable=False)
    period_end = db.Column(db.DateTime, nullable=False)
    total_alerts = db.Column(db.Integer, default=0)
    total_blocked = db.Column(db.Integer, default=0)
    total_packets = db.Column(db.Integer, default=0)
    file_path = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "report_type": self.report_type,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "total_alerts": self.total_alerts,
            "total_blocked": self.total_blocked,
            "total_packets": self.total_packets,
            "file_path": self.file_path,
        }

from datetime import datetime
from database import db


class PacketLog(db.Model):
    __tablename__ = "packet_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    destination_ip = db.Column(db.String(45), nullable=True, index=True)
    protocol = db.Column(db.String(16), nullable=True, index=True)  # TCP/UDP/ICMP/ARP/DNS
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    packet_size = db.Column(db.Integer, nullable=True)
    flags = db.Column(db.String(32), nullable=True)
    summary = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "packet_size": self.packet_size,
            "flags": self.flags,
            "summary": self.summary,
        }

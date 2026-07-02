"""
Aggregates alert/packet/block data over a date range for use in the Reports
page and PDF export. Uses pandas for convenient grouping/summary stats.
"""

from datetime import datetime, timedelta
import pandas as pd

from models.alert import Alert
from models.blocked_ip import BlockedIP
from models.packet_log import PacketLog


def _period_bounds(report_type, reference=None):
    reference = reference or datetime.utcnow()
    if report_type == "Daily":
        start = reference.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
    elif report_type == "Weekly":
        start = (reference - timedelta(days=reference.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=7)
    elif report_type == "Monthly":
        start = reference.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if start.month == 12:
            end = start.replace(year=start.year + 1, month=1)
        else:
            end = start.replace(month=start.month + 1)
    else:
        raise ValueError("report_type must be Daily, Weekly, or Monthly")
    return start, end


def build_report_data(report_type, reference=None):
    start, end = _period_bounds(report_type, reference)

    alerts = Alert.query.filter(Alert.timestamp >= start, Alert.timestamp < end).all()
    blocks = BlockedIP.query.filter(BlockedIP.blocked_at >= start, BlockedIP.blocked_at < end).all()
    packet_count = PacketLog.query.filter(PacketLog.timestamp >= start, PacketLog.timestamp < end).count()

    alert_rows = [{
        "attack_type": a.attack_type,
        "severity": a.severity,
        "source_ip": a.source_ip,
        "threat_score": a.threat_score,
    } for a in alerts]

    df = pd.DataFrame(alert_rows) if alert_rows else pd.DataFrame(
        columns=["attack_type", "severity", "source_ip", "threat_score"])

    by_type = df["attack_type"].value_counts().to_dict() if not df.empty else {}
    by_severity = df["severity"].value_counts().to_dict() if not df.empty else {}
    top_sources = df["source_ip"].value_counts().head(10).to_dict() if not df.empty else {}
    avg_score = round(df["threat_score"].mean(), 1) if not df.empty else 0

    return {
        "report_type": report_type,
        "period_start": start,
        "period_end": end,
        "total_alerts": len(alerts),
        "total_blocked": len(blocks),
        "total_packets": packet_count,
        "by_attack_type": by_type,
        "by_severity": by_severity,
        "top_source_ips": top_sources,
        "average_threat_score": avg_score,
        "alerts": alerts,
        "blocks": blocks,
    }

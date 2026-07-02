"""
PDF generation using ReportLab. Produces the periodic threat report PDF and
generic tabular log export PDFs.
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)

BRAND_COLOR = colors.HexColor("#0d6efd")
DARK_COLOR = colors.HexColor("#0a1929")


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CSTitle", fontSize=20, leading=24, textColor=DARK_COLOR, spaceAfter=6))
    styles.add(ParagraphStyle(name="CSSubtitle", fontSize=11, textColor=colors.grey, spaceAfter=12))
    styles.add(ParagraphStyle(name="CSHeading", fontSize=13, textColor=BRAND_COLOR, spaceBefore=14, spaceAfter=6))
    return styles


def generate_report_pdf(report_data, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             leftMargin=2 * cm, rightMargin=2 * cm,
                             topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    styles = _styles()
    elements = []

    elements.append(Paragraph("CyberShield IDS/IPS", styles["CSTitle"]))
    elements.append(Paragraph(
        f"{report_data['report_type']} Security Report &nbsp;|&nbsp; "
        f"{report_data['period_start'].strftime('%Y-%m-%d')} to "
        f"{report_data['period_end'].strftime('%Y-%m-%d')}",
        styles["CSSubtitle"],
    ))

    summary_data = [
        ["Total Alerts", str(report_data["total_alerts"])],
        ["Total IPs Blocked", str(report_data["total_blocked"])],
        ["Total Packets Captured", str(report_data["total_packets"])],
        ["Average Threat Score", str(report_data["average_threat_score"])],
    ]
    summary_table = Table(summary_data, colWidths=[8 * cm, 6 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef4ff")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8e3")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)

    elements.append(Paragraph("Alerts by Attack Type", styles["CSHeading"]))
    type_rows = [["Attack Type", "Count"]] + [[k, str(v)] for k, v in report_data["by_attack_type"].items()]
    if len(type_rows) == 1:
        type_rows.append(["No alerts in this period", "-"])
    elements.append(_styled_table(type_rows))

    elements.append(Paragraph("Alerts by Severity", styles["CSHeading"]))
    sev_rows = [["Severity", "Count"]] + [[k, str(v)] for k, v in report_data["by_severity"].items()]
    if len(sev_rows) == 1:
        sev_rows.append(["No alerts in this period", "-"])
    elements.append(_styled_table(sev_rows))

    elements.append(Paragraph("Top Source IPs", styles["CSHeading"]))
    ip_rows = [["Source IP", "Alert Count"]] + [[k, str(v)] for k, v in report_data["top_source_ips"].items()]
    if len(ip_rows) == 1:
        ip_rows.append(["No alerts in this period", "-"])
    elements.append(_styled_table(ip_rows))

    elements.append(Spacer(1, 16))
    elements.append(Paragraph(
        f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC by CyberShield IDS/IPS",
        styles["CSSubtitle"],
    ))

    doc.build(elements)
    return output_path


def _styled_table(rows):
    table = Table(rows, colWidths=[10 * cm, 4 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_COLOR),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8e3")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
    ]))
    return table


def generate_table_pdf(title, headers, rows, output_path):
    """Generic export used by the Logs page (alerts / packets / blocked IPs)."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                             topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    styles = _styles()
    elements = [Paragraph(title, styles["CSTitle"]),
                Paragraph(f"Exported {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", styles["CSSubtitle"])]

    data = [headers] + rows
    col_width = (A4[0] - 3 * cm) / max(len(headers), 1)
    table = Table(data, colWidths=[col_width] * len(headers), repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_COLOR),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8e3")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
    ]))
    elements.append(table)
    doc.build(elements)
    return output_path

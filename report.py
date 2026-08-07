"""
SecureScan - PDF, CSV, and JSON Report Generation Engine
"""
import os
import json
import csv
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'reports')

def ensure_reports_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_pdf_report(scan_data):
    """Generates a professional cybersecurity audit report PDF using ReportLab."""
    ensure_reports_dir()
    scan_id = scan_data["id"]
    pdf_filename = f"SecureScan_Report_{scan_id}.pdf"
    file_path = os.path.join(REPORTS_DIR, pdf_filename)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Cyber Security PDF Styles
    title_style = ParagraphStyle(
        'CyberTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#00FF88'),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'CyberSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        textColor=colors.HexColor('#8A99AD'),
        spaceAfter=15
    )

    heading2_style = ParagraphStyle(
        'CyberHeading2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#00C8FF'),
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'CyberBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#222222')
    )

    badge_style_open = ParagraphStyle('OpenBadge', parent=body_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#00AA44'))
    badge_style_closed = ParagraphStyle('ClosedBadge', parent=body_style, textColor=colors.HexColor('#CC0000'))
    badge_style_filtered = ParagraphStyle('FilteredBadge', parent=body_style, textColor=colors.HexColor('#CC9900'))

    elements = []

    # Title & Header Banner
    elements.append(Paragraph("SECURESCAN AUDIT REPORT", title_style))
    elements.append(Paragraph(f"Target: {scan_data['target']} ({scan_data['ip']}) | Generated: {scan_data.get('created_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00FF88'), spaceBefore=0, spaceAfter=15))

    # Executive Summary Card Table
    risk_score = scan_data.get("risk_score", 0)
    risk_level = "CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW"))

    summary_data = [
        [Paragraph("<b>Target Host / IP:</b>", body_style), Paragraph(f"{scan_data['target']} ({scan_data['ip']})", body_style),
         Paragraph("<b>Scan Date:</b>", body_style), Paragraph(str(scan_data.get('created_at', 'N/A')), body_style)],
        [Paragraph("<b>Reverse DNS:</b>", body_style), Paragraph(str(scan_data.get('reverse_dns', 'N/A')), body_style),
         Paragraph("<b>Scan Duration:</b>", body_style), Paragraph(f"{scan_data.get('duration_seconds', 0)} seconds", body_style)],
        [Paragraph("<b>Total Scanned Ports:</b>", body_style), Paragraph(str(scan_data.get('total_ports', 0)), body_style),
         Paragraph("<b>OS Prediction:</b>", body_style), Paragraph(str(scan_data.get('os_guess', 'N/A')), body_style)],
        [Paragraph("<b>Open Ports:</b>", body_style), Paragraph(f"<font color='#00AA44'><b>{scan_data.get('open_ports_count', 0)}</b></font>", body_style),
         Paragraph("<b>Threat Risk Level:</b>", body_style), Paragraph(f"<b>{risk_level} ({risk_score}/100)</b>", body_style)]
    ]

    t_summary = Table(summary_data, colWidths=[120, 150, 120, 150])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F4F6F9')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#DCDFE6')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 15))

    # Security Remediation Recommendations Section
    elements.append(Paragraph("SECURITY RECOMMENDATIONS & REMEDIATION", heading2_style))
    recs = scan_data.get("recommendations", [])
    if recs:
        rec_table_data = [["Port", "Title / Severity", "Impact & Action Item"]]
        for r in recs:
            severity_str = f"<b>{r.get('title', '')}</b><br/><font color='#D9534F'>Severity: {r.get('severity', 'Medium')}</font>"
            action_str = f"<b>Impact:</b> {r.get('impact', '')}<br/><b>Remediation:</b> {r.get('action', '')}"
            rec_table_data.append([
                Paragraph(str(r.get('port', 'General')), body_style),
                Paragraph(severity_str, body_style),
                Paragraph(action_str, body_style)
            ])
        t_recs = Table(rec_table_data, colWidths=[50, 190, 300])
        t_recs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00C8FF')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        elements.append(t_recs)
    else:
        elements.append(Paragraph("No critical vulnerabilities detected on scanned open ports.", body_style))

    elements.append(Spacer(1, 15))

    # Open Ports Results Table
    elements.append(Paragraph("OPEN PORTS ENUMERATION & SERVICE DETAILS", heading2_style))
    results = scan_data.get("results", [])
    open_results = [r for r in results if r["status"] == "Open"]

    if open_results:
        port_table_data = [["Port", "Status", "Service", "Protocol", "Response Time", "Banner / Details"]]
        for r in open_results:
            p_style = badge_style_open if r["status"] == "Open" else (badge_style_filtered if r["status"] == "Filtered" else badge_style_closed)
            banner_text = r.get("banner", "") or "-"
            if len(banner_text) > 40:
                banner_text = banner_text[:40] + "..."
            
            port_table_data.append([
                Paragraph(str(r["port"]), body_style),
                Paragraph(r["status"], p_style),
                Paragraph(r["service"], body_style),
                Paragraph(r["protocol"], body_style),
                Paragraph(f"{r['response_time_ms']} ms", body_style),
                Paragraph(banner_text, body_style)
            ])

        t_ports = Table(port_table_data, colWidths=[45, 55, 90, 55, 80, 215])
        t_ports.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('PADDING', (0,0), (-1,-1), 4),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(t_ports)
    else:
        elements.append(Paragraph("No open ports were identified during this scan.", body_style))

    # Disclaimer Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceBefore=5, spaceAfter=8))
    disclaimer_text = "<b>DISCLAIMER:</b> SecureScan is intended strictly for authorized security auditing and educational testing. Scanning unauthorized targets is strictly prohibited."
    elements.append(Paragraph(disclaimer_text, ParagraphStyle('Disc', parent=body_style, fontSize=7, textColor=colors.HexColor('#64748B'))))

    doc.build(elements)
    return file_path, pdf_filename

def generate_csv_report(scan_data):
    """Generates CSV format export of scan results."""
    ensure_reports_dir()
    scan_id = scan_data["id"]
    csv_filename = f"SecureScan_Report_{scan_id}.csv"
    file_path = os.path.join(REPORTS_DIR, csv_filename)

    with open(file_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "IP", "Port", "Status", "Service", "Protocol", "Response Time (ms)", "Risk Level", "Banner"])
        
        for r in scan_data.get("results", []):
            writer.writerow([
                scan_data["target"],
                scan_data["ip"],
                r["port"],
                r["status"],
                r["service"],
                r["protocol"],
                r["response_time_ms"],
                r["risk_level"],
                r.get("banner", "")
            ])

    return file_path, csv_filename

def generate_json_report(scan_data):
    """Generates JSON format export of full scan payload."""
    ensure_reports_dir()
    scan_id = scan_data["id"]
    json_filename = f"SecureScan_Report_{scan_id}.json"
    file_path = os.path.join(REPORTS_DIR, json_filename)

    with open(file_path, mode='w', encoding='utf-8') as f:
        json.dump(scan_data, f, indent=2)

    return file_path, json_filename

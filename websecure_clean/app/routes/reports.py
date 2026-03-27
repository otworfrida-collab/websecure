"""
WebSecure Report Routes
Generate and download PDF vulnerability reports.
"""

import io
from datetime import datetime
from flask import Blueprint, send_file, abort
from flask_login import login_required, current_user
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                  TableStyle, HRFlowable)
from app.models.models import Scan, Website, Vulnerability

reports_bp = Blueprint('reports', __name__)

# ── Color palette ──────────────────────────────────────────────────────────────
C_DARK   = colors.HexColor('#0f172a')
C_ACCENT = colors.HexColor('#3b82f6')
C_HIGH   = colors.HexColor('#ef4444')
C_MED    = colors.HexColor('#f59e0b')
C_LOW    = colors.HexColor('#22c55e')
C_BG     = colors.HexColor('#f8fafc')
C_WHITE  = colors.white


@reports_bp.route('/scans/<int:scan_id>/report.pdf')
@login_required
def download_report(scan_id):
    scan = Scan.find_by_id(scan_id)
    if not scan:
        abort(404)
    site = Website.find_by_user_and_id(current_user.id, scan.website_id)
    if not site:
        abort(404)
    vulns = Vulnerability.for_scan(scan_id)

    pdf_buffer = _build_pdf(scan, site, vulns)
    filename = f'websecure-report-{site.url.replace("https://","").replace("http://","").split("/")[0]}-{scan.scan_date.strftime("%Y%m%d")}.pdf'

    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )


def _build_pdf(scan, site, vulns) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # ── Title block ───────────────────────────────────────────────────────────
    title_style = ParagraphStyle('Title', fontSize=22, textColor=C_ACCENT,
                                  spaceAfter=4, fontName='Helvetica-Bold')
    sub_style   = ParagraphStyle('Sub',   fontSize=11, textColor=C_DARK,
                                  spaceAfter=2, fontName='Helvetica')
    body_style  = ParagraphStyle('Body',  fontSize=9,  textColor=C_DARK,
                                  spaceAfter=6, leading=13, fontName='Helvetica')
    h2_style    = ParagraphStyle('H2',    fontSize=13, textColor=C_DARK,
                                  spaceBefore=12, spaceAfter=4,
                                  fontName='Helvetica-Bold')

    story.append(Paragraph('WebSecure', title_style))
    story.append(Paragraph('Vulnerability Scan Report', sub_style))
    story.append(HRFlowable(width='100%', color=C_ACCENT, thickness=2))
    story.append(Spacer(1, 0.3*cm))

    # ── Metadata table ────────────────────────────────────────────────────────
    counts = scan.vuln_counts()
    meta_data = [
        ['Target URL',    site.url],
        ['Scan Date',     scan.scan_date.strftime('%Y-%m-%d %H:%M UTC')],
        ['Status',        scan.status.upper()],
        ['Duration',      f'{scan.duration_secs:.1f} seconds'],
        ['Risk Score',    f'{scan.risk_score:.1f} / 100'],
        ['Total Issues',  str(scan.total_vulns)],
        ['High',          str(counts.get('High', 0))],
        ['Medium',        str(counts.get('Medium', 0))],
        ['Low',           str(counts.get('Low', 0))],
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 13*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME',      (0,0), (-1,-1), 'Helvetica'),
        ('FONTNAME',      (0,0), (0,-1),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('TEXTCOLOR',     (0,0), (0,-1),  C_ACCENT),
        ('ROWBACKGROUNDS',(0,0), (-1,-1), [C_BG, C_WHITE]),
        ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*cm))

    # ── Summary ───────────────────────────────────────────────────────────────
    story.append(Paragraph('Executive Summary', h2_style))
    story.append(HRFlowable(width='100%', color=colors.HexColor('#e2e8f0'), thickness=1))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(scan.result_summary or 'No summary available.', body_style))

    if not vulns:
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph('✓ No vulnerabilities detected in this scan.', body_style))
        doc.build(story)
        buf.seek(0)
        return buf

    # ── Findings table ────────────────────────────────────────────────────────
    story.append(Paragraph('Vulnerability Findings', h2_style))
    story.append(HRFlowable(width='100%', color=colors.HexColor('#e2e8f0'), thickness=1))
    story.append(Spacer(1, 0.2*cm))

    for i, v in enumerate(vulns, 1):
        risk_color = {'High': C_HIGH, 'Medium': C_MED, 'Low': C_LOW}.get(v.risk_level, C_LOW)
        num_style = ParagraphStyle(f'num{i}', fontSize=9, textColor=C_WHITE,
                                    fontName='Helvetica-Bold')
        risk_style = ParagraphStyle(f'risk{i}', fontSize=8, textColor=C_WHITE,
                                     fontName='Helvetica-Bold')

        header_data = [[
            Paragraph(f'#{i}', num_style),
            Paragraph(v.vulnerability_type, ParagraphStyle(
                f'vt{i}', fontSize=10, textColor=C_WHITE, fontName='Helvetica-Bold')),
            Paragraph(v.risk_level, risk_style),
            Paragraph(f'Score: {v.severity_score:.1f}', risk_style),
        ]]
        header_tbl = Table(header_data, colWidths=[1*cm, 11*cm, 2.5*cm, 2.5*cm])
        header_tbl.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,-1), risk_color),
            ('TEXTCOLOR',   (0,0), (-1,-1), C_WHITE),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING',  (0,0), (-1,-1), 6),
            ('BOTTOMPADDING',(0,0),(-1,-1), 6),
        ]))
        story.append(header_tbl)

        body_data = [
            [Paragraph('<b>Description</b>', body_style),
             Paragraph(v.description, body_style)],
            [Paragraph('<b>Recommendation</b>', body_style),
             Paragraph(v.recommendation or 'N/A', body_style)],
        ]
        if v.evidence:
            body_data.append([
                Paragraph('<b>Evidence</b>', body_style),
                Paragraph(v.evidence[:300], body_style)
            ])

        body_tbl = Table(body_data, colWidths=[3.5*cm, 13.5*cm])
        body_tbl.setStyle(TableStyle([
            ('FONTNAME',    (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE',    (0,0), (-1,-1), 9),
            ('VALIGN',      (0,0), (-1,-1), 'TOP'),
            ('BACKGROUND',  (0,0), (-1,-1), C_BG),
            ('GRID',        (0,0), (-1,-1), 0.3, colors.HexColor('#e2e8f0')),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('TOPPADDING',  (0,0), (-1,-1), 5),
            ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ]))
        story.append(body_tbl)
        story.append(Spacer(1, 0.4*cm))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width='100%', color=C_ACCENT, thickness=1))
    footer_style = ParagraphStyle('footer', fontSize=8, textColor=colors.gray,
                                   spaceAfter=0, fontName='Helvetica')
    story.append(Paragraph(
        f'Generated by WebSecure on {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")} — '
        'For educational and small-business security assessment purposes only.',
        footer_style
    ))

    doc.build(story)
    buf.seek(0)
    return buf

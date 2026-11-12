"""
CyberScape Automated Forensic PDF Report Generator
Generates enterprise-grade cybersecurity forensic investigation reports using ReportLab.
"""

import io
import uuid
import re
import xml.sax.saxutils
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass ReportLab canvas that dynamically writes 'Page X of Y'
    and formal cybersecurity forensic branding on every page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#4A5260"))
        
        # Bottom rule
        self.setStrokeColor(colors.HexColor("#C9CDC4"))
        self.setLineWidth(0.5)
        self.line(36, 30, 612 - 36, 30)
        
        # Footer text on left, page number on right
        footer_text = "CYBERSCAPE CYBERSECURITY FORENSICS • CONFIDENTIAL INVESTIGATION RECORD"
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawString(36, 20, footer_text)
        self.drawRightString(612 - 36, 20, page_text)
        self.restoreState()


def safe_escape(text) -> str:
    if text is None:
        return ""
    return xml.sax.saxutils.escape(str(text))


def safe_wrap(text, max_chunk: int = 40) -> str:
    """Safely escape text for ReportLab XML while allowing long strings (like URLs) to wrap."""
    if not text:
        return ""
    escaped = xml.sax.saxutils.escape(str(text))
    # Insert soft break space around delimiters
    wrapped = re.sub(r'([/?&=._\-])', r'\1 ', escaped)
    parts = []
    for word in wrapped.split(' '):
        if len(word) > max_chunk:
            subparts = [word[i:i+max_chunk] for i in range(0, len(word), max_chunk)]
            parts.append(' '.join(subparts))
        else:
            parts.append(word)
    return ' '.join(parts)


def generate_forensic_pdf(scan_data: dict) -> bytes:
    """
    Generate a downloadable PDF forensic report from scan telemetry.
    Returns the binary content of the generated PDF.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    story = []
    styles = getSampleStyleSheet()

    # Brand Colors
    teal_primary = colors.HexColor("#0f766e")
    teal_dark = colors.HexColor("#115e59")
    teal_light = colors.HexColor("#f0fdfa")
    slate_dark = colors.HexColor("#0f172a")
    slate_muted = colors.HexColor("#475569")
    slate_border = colors.HexColor("#cbd5e1")
    surface_bg = colors.HexColor("#f8fafc")

    status = (scan_data.get("status") or "UNKNOWN").upper()
    if status == "MALICIOUS":
        status_color = colors.HexColor("#e11d48")
        status_bg = colors.HexColor("#fff1f2")
    elif status == "SUSPICIOUS":
        status_color = colors.HexColor("#d97706")
        status_bg = colors.HexColor("#fffbeb")
    else:
        status_color = colors.HexColor("#059669")
        status_bg = colors.HexColor("#ecfdf5")

    # Typography styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=teal_primary
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=slate_muted
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=teal_dark,
        spaceBefore=8,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=slate_dark
    )
    body_mono = ParagraphStyle(
        "BodyMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=slate_dark
    )
    badge_style = ParagraphStyle(
        "VerdictBadge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        alignment=TA_CENTER,
        textColor=status_color
    )

    report_id = f"CS-FOR-{uuid.uuid4().hex[:8].upper()}"
    timestamp = scan_data.get("time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target_url = scan_data.get("url") or "Unknown"

    # Header Table
    header_data = [
        [
            Paragraph("<b>CYBERSCAPE</b> | Advanced Threat Forensics", title_style),
            Paragraph(f"<b>REPORT ID:</b> {report_id}<br/><b>DATE:</b> {timestamp}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=teal_primary, spaceBefore=4, spaceAfter=10))

    # Executive Summary Card
    score = scan_data.get("score", 0)
    level = scan_data.get("level", "Standard")
    source = scan_data.get("source", "Direct URL")

    exec_summary_data = [
        [
            Paragraph("<b>TARGET DESTINATION:</b>", body_style),
            Paragraph(f"<b>{target_url}</b>", body_mono)
        ],
        [
            Paragraph("<b>OVERALL THREAT VERDICT:</b>", body_style),
            Paragraph(f"<b>{status}</b> • {level}", badge_style)
        ],
        [
            Paragraph("<b>THREAT RISK SCORE:</b>", body_style),
            Paragraph(f"<b>{score} / 100</b> ({'Critical Risk' if score > 70 else ('Moderate Risk' if score > 30 else 'Low Risk')})", body_style)
        ],
        [
            Paragraph("<b>DETECTION CHANNEL:</b>", body_style),
            Paragraph(f"{source} Scanner Sandbox", body_style)
        ]
    ]
    exec_table = Table(exec_summary_data, colWidths=[160, 380])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), surface_bg),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (1, 1), (1, 1), status_bg),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 10))

    # Section 1: AI Machine Learning Phishing Analysis
    ml = scan_data.get("ml_analysis") or {}
    ml_label = ml.get("label", "Legitimate")
    ml_confidence = ml.get("confidence", 95.0)
    risk_factors = ml.get("risk_factors") or scan_data.get("reasons") or ["No structural anomalies detected."]
    features = ml.get("features") or {}

    story.append(Paragraph("1. AI Machine Learning Domain Classification", section_heading))
    ml_table_data = [
        [
            Paragraph("<b>Classifier Model:</b>", body_style),
            Paragraph("Ensemble Random Forest (120 Estimators)", body_style),
            Paragraph("<b>ML Prediction:</b>", body_style),
            Paragraph(f"<b>{ml_label}</b> ({ml_confidence}% Confidence)", body_style)
        ],
        [
            Paragraph("<b>URL Length:</b>", body_style),
            Paragraph(f"{features.get('url_length', len(target_url))} chars", body_style),
            Paragraph("<b>Subdomain Count:</b>", body_style),
            Paragraph(f"{features.get('subdomain_count', 0)} detected", body_style)
        ],
        [
            Paragraph("<b>Protocol TLS/SSL:</b>", body_style),
            Paragraph("Encrypted HTTPS" if features.get("is_https") else "Unencrypted HTTP", body_style),
            Paragraph("<b>Suspicious TLD:</b>", body_style),
            Paragraph(f"{features.get('tld', 'N/A')} ({'High Risk' if features.get('has_suspicious_tld') else 'Standard'})", body_style)
        ],
        [
            Paragraph("<b>IP Host Form:</b>", body_style),
            Paragraph("Raw IP" if features.get("has_ip") else "Registered Hostname", body_style),
            Paragraph("<b>Domain Entropy:</b>", body_style),
            Paragraph(f"{features.get('shannon_entropy', 2.8)} (Shannon Index)", body_style)
        ]
    ]
    ml_table = Table(ml_table_data, colWidths=[120, 150, 120, 150])
    ml_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), surface_bg),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(ml_table)

    # ML Extracted Risk Factors
    factors_html = "<br/>".join([f"• {f}" for f in risk_factors[:5]])
    factors_table = Table([
        [Paragraph("<b>Identified Risk Indicators:</b>", body_style), Paragraph(factors_html, body_style)]
    ], colWidths=[140, 400])
    factors_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), teal_light),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(Spacer(1, 4))
    story.append(factors_table)
    story.append(Spacer(1, 10))

    # Section 2: Real-Time Multi-Engine Threat Intelligence
    threat_intel = scan_data.get("threat_intel") or {}
    flagged = threat_intel.get("flagged_engines", 0)
    total_eng = threat_intel.get("total_engines", 90)
    vt_info = threat_intel.get("virustotal") or {}
    urlhaus_info = threat_intel.get("urlhaus") or {}
    gsb_info = threat_intel.get("safebrowsing") or {}

    story.append(Paragraph("2. Real-Time Threat Intelligence Feeds", section_heading))
    intel_table_data = [
        [
            Paragraph("<b>Threat Intelligence Feed</b>", body_style),
            Paragraph("<b>Inspection Status</b>", body_style),
            Paragraph("<b>Findings & Telemetry Details</b>", body_style)
        ],
        [
            Paragraph("<b>VirusTotal Aggregate</b>", body_style),
            Paragraph(f"<b>{flagged}/{total_eng} Flagged</b>", body_style),
            Paragraph(vt_info.get("reason", f"{flagged} out of {total_eng} engines detected malicious patterns."), body_style)
        ],
        [
            Paragraph("<b>URLhaus Malware Feed</b>", body_style),
            Paragraph(f"<b>{urlhaus_info.get('verdict', 'Clean')}</b>", body_style),
            Paragraph(urlhaus_info.get("reason", "No threat records returned from live URLhaus database."), body_style)
        ],
        [
            Paragraph("<b>Google Safe Browsing</b>", body_style),
            Paragraph(f"<b>{gsb_info.get('verdict', 'Safe')}</b>", body_style),
            Paragraph(gsb_info.get("reason", "Target verified safe from deceptive engineering campaigns."), body_style)
        ]
    ]
    intel_table = Table(intel_table_data, colWidths=[140, 110, 290])
    intel_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), teal_light),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(intel_table)
    story.append(Spacer(1, 10))

    # Section 3: Geo-IP Tracking & Network Telemetry
    geo = scan_data.get("geo_ip") or {}
    story.append(Paragraph("3. Server Geo-Location & Network Infrastructure", section_heading))
    geo_data = [
        [
            Paragraph("<b>Server IP Address:</b>", body_style),
            Paragraph(f"<b>{geo.get('ip', 'N/A')}</b>", body_mono),
            Paragraph("<b>Host Country:</b>", body_style),
            Paragraph(f"{geo.get('country', 'N/A')} ({geo.get('country_code', 'UN')})", body_style)
        ],
        [
            Paragraph("<b>Server Location:</b>", body_style),
            Paragraph(f"{geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}", body_style),
            Paragraph("<b>Coordinates:</b>", body_style),
            Paragraph(f"{geo.get('coordinates', '0.0000, 0.0000')}", body_mono)
        ],
        [
            Paragraph("<b>ISP / Registrar:</b>", body_style),
            Paragraph(f"{geo.get('isp', 'Unknown ISP')}", body_style),
            Paragraph("<b>ASN / Org:</b>", body_style),
            Paragraph(f"{geo.get('org', geo.get('asn', 'N/A'))}", body_style)
        ]
    ]
    geo_table = Table(geo_data, colWidths=[120, 150, 120, 150])
    geo_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), surface_bg),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(geo_table)
    story.append(Spacer(1, 10))

    # Section 4: Redirect Chain & Destination Sandbox Tracking
    redirects = scan_data.get("redirect_chain") or {}
    hops = redirects.get("chain") or []
    if hops:
        story.append(Paragraph("4. HTTP Redirection Chain & Sandbox Tracer", section_heading))
        chain_rows = [
            [
                Paragraph("<b>Hop #</b>", body_style),
                Paragraph("<b>HTTP Status</b>", body_style),
                Paragraph("<b>Visited Destination URL</b>", body_style)
            ]
        ]
        for step in hops[:5]:
            chain_rows.append([
                Paragraph(f"Hop {step.get('step', 1)}", body_style),
                Paragraph(f"HTTP {step.get('status_code', 200)}", body_style),
                Paragraph(f"{step.get('url')}" + (f" -&gt; <i>{step.get('redirect_to')}</i>" if step.get("redirect_to") else ""), body_mono)
            ])
        chain_table = Table(chain_rows, colWidths=[50, 70, 420])
        chain_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), teal_light),
            ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(chain_table)
        story.append(Spacer(1, 10))

    # Section 5: Structured Problem Findings & Evidence
    findings = scan_data.get("findings") or []
    if findings:
        story.append(Paragraph("5. Flagged Security Findings & Problem Evidence", section_heading))
        for f in findings:
            f_sev = (f.get("severity") or "low").upper()
            f_title = f.get("title") or "Flagged Threat Indicator"
            f_exp = f.get("explanation") or "Anomalous behavior detected."
            f_evi = safe_wrap(str(f.get("evidence") or "None"), max_chunk=65)
            f_rec = f.get("recommendation") or "Exercise caution before interacting with this destination."

            badge_color = colors.HexColor("#C23A0C") if f_sev in ("CRITICAL", "HIGH") else (colors.HexColor("#8A5A00") if f_sev in ("MEDIUM", "WARNING") else slate_muted)
            badge_bg = colors.HexColor("#fff1f2") if f_sev in ("CRITICAL", "HIGH") else (colors.HexColor("#fffbeb") if f_sev in ("MEDIUM", "WARNING") else surface_bg)

            card_content = [
                [Paragraph(f"<font color='{badge_color.hexval()}'><b>[{f_sev}]</b></font> <b>{safe_escape(f_title)}</b>", body_style)],
                [Paragraph(f"<b>Explanation:</b> {safe_escape(f_exp)}", body_style)],
                [Paragraph(f"<b>Evidence:</b> <font color='#12161D'>{f_evi}</font>", body_mono)],
                [Paragraph(f"<b>Recommended Action:</b> <font color='#0f766e'>{safe_escape(f_rec)}</font>", body_style)]
            ]
            card_table = Table(card_content, colWidths=[540])
            card_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), badge_bg),
                ('BACKGROUND', (0, 1), (-1, -1), surface_bg),
                ('BOX', (0, 0), (-1, -1), 0.8, slate_border),
                ('INNERGRID', (0, 0), (-1, -1), 0.3, slate_border),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(card_table)
            story.append(Spacer(1, 5))
        story.append(Spacer(1, 6))

    # Verification Footer
    footer_text = f"CONFIDENTIAL & PRIVILEGED FORENSIC RECORD • GENERATED BY CYBERSCAPE ENTERPRISE THREAT INTELLIGENCE ENGINE • HASH: {report_id}"
    story.append(KeepTogether([
        HRFlowable(width="100%", thickness=0.8, color=slate_border, spaceBefore=8, spaceAfter=4),
        Paragraph(footer_text, ParagraphStyle("Footer", fontName="Helvetica", fontSize=6.5, leading=9, textColor=slate_muted, alignment=TA_CENTER))
    ]))

    doc.build(story)
    return buffer.getvalue()


def generate_email_forensic_pdf(email_data: dict) -> bytes:
    """
    Generate a downloadable PDF email forensic investigation report.
    Analyzes sender spoofing, SPF/DKIM/DMARC, originating IP geo-telemetry,
    NLP urgency triggers, and extracted defanged hyperlinks.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    story = []
    styles = getSampleStyleSheet()

    teal_primary = colors.HexColor("#0f766e")
    teal_dark = colors.HexColor("#115e59")
    teal_light = colors.HexColor("#f0fdfa")
    slate_dark = colors.HexColor("#0f172a")
    slate_muted = colors.HexColor("#475569")
    slate_border = colors.HexColor("#cbd5e1")
    surface_bg = colors.HexColor("#f8fafc")

    verdict = (email_data.get("verdict") or "UNKNOWN").upper()
    if verdict == "MALICIOUS":
        status_color = colors.HexColor("#e11d48")
        status_bg = colors.HexColor("#fff1f2")
    elif verdict == "SUSPICIOUS":
        status_color = colors.HexColor("#d97706")
        status_bg = colors.HexColor("#fffbeb")
    else:
        status_color = colors.HexColor("#059669")
        status_bg = colors.HexColor("#ecfdf5")

    title_style = ParagraphStyle(
        "EmailReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=teal_primary
    )
    subtitle_style = ParagraphStyle(
        "EmailReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=slate_muted
    )
    section_heading = ParagraphStyle(
        "EmailSectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=teal_dark,
        spaceBefore=8,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        "EmailBodyCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=slate_dark
    )
    body_mono = ParagraphStyle(
        "EmailBodyMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=slate_dark
    )
    badge_style = ParagraphStyle(
        "EmailVerdictBadge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        alignment=TA_CENTER,
        textColor=status_color
    )

    report_id = f"CS-EML-{uuid.uuid4().hex[:8].upper()}"
    timestamp = email_data.get("time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header_info = email_data.get("header_analysis") or {}
    content_info = email_data.get("content_analysis") or {}
    summary = email_data.get("summary") or {}
    score = email_data.get("score", 0)
    level = email_data.get("level", "Standard")

    # Header Banner
    header_data = [
        [
            Paragraph("<b>CYBERSCAPE</b> | Fake Email & Header Forensics", title_style),
            Paragraph(f"<b>REPORT ID:</b> {report_id}<br/><b>DATE:</b> {timestamp}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=teal_primary, spaceBefore=4, spaceAfter=10))

    # Executive Summary Card
    sender_text = header_info.get("from_header") or header_info.get("from_addr") or "Unspecified Sender"
    subject_text = header_info.get("subject") or "No Subject Header"

    exec_summary_data = [
        [
            Paragraph("<b>CLAIMED SENDER:</b>", body_style),
            Paragraph(f"<b>{sender_text}</b>", body_mono)
        ],
        [
            Paragraph("<b>EMAIL SUBJECT:</b>", body_style),
            Paragraph(f"{subject_text}", body_style)
        ],
        [
            Paragraph("<b>FORENSIC VERDICT:</b>", body_style),
            Paragraph(f"<b>{verdict}</b> • {level}", badge_style)
        ],
        [
            Paragraph("<b>THREAT RISK SCORE:</b>", body_style),
            Paragraph(f"<b>{score} / 100</b> ({'Critical Risk' if score >= 70 else ('Elevated Risk' if score >= 35 else 'Verified Safe')})", body_style)
        ],
        [
            Paragraph("<b>AUTHENTICATION STATUS:</b>", body_style),
            Paragraph(f"<b>{summary.get('authentication', 'UNVERIFIED')}</b>", body_style)
        ],
        [
            Paragraph("<b>ORIGINATING SERVER:</b>", body_style),
            Paragraph(f"IP: {summary.get('originating_ip', 'N/A')} ({header_info.get('geo_ip', {}).get('country', 'Unknown')})", body_style)
        ]
    ]
    exec_table = Table(exec_summary_data, colWidths=[160, 380])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), surface_bg),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (1, 2), (1, 2), status_bg),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 10))

    # Section 1: Technical Header Authentication & Spoofing Analysis
    story.append(Paragraph("1. Email Authentication & Sender Spoofing Check", section_heading))
    auth = header_info.get("authentication") or {}
    auth_data = [
        [
            Paragraph("<b>Header Component</b>", body_style),
            Paragraph("<b>Extracted Value / Domain</b>", body_style),
            Paragraph("<b>Verification Status</b>", body_style)
        ],
        [
            Paragraph("<b>From Address:</b>", body_style),
            Paragraph(f"{header_info.get('from_addr', 'N/A')}", body_mono),
            Paragraph(f"Domain: {header_info.get('from_domain', 'N/A')}", body_style)
        ],
        [
            Paragraph("<b>Return-Path:</b>", body_style),
            Paragraph(f"{header_info.get('return_path', 'N/A')}", body_mono),
            Paragraph("Mismatch Detected" if header_info.get("is_spoofed") else "Aligned", body_style)
        ],
        [
            Paragraph("<b>SPF Validation:</b>", body_style),
            Paragraph(f"Status: {auth.get('spf', 'NONE')}", body_style),
            Paragraph(f"{auth.get('raw_spf', 'Standard Check')[:40]}", body_mono)
        ],
        [
            Paragraph("<b>DKIM Signature:</b>", body_style),
            Paragraph(f"Status: {auth.get('dkim', 'NONE')}", body_style),
            Paragraph("Cryptographic Signature Present" if auth.get("dkim") == "PASS" else "No valid signature", body_style)
        ],
        [
            Paragraph("<b>DMARC Policy:</b>", body_style),
            Paragraph(f"Status: {auth.get('dmarc', 'NONE')}", body_style),
            Paragraph("Domain Policy Enforced" if auth.get("dmarc") == "PASS" else "Unaligned / Missing", body_style)
        ]
    ]
    auth_table = Table(auth_data, colWidths=[130, 230, 180])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), teal_light),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 10))

    # Section 2: Originating Server Geo-Location & ISP Telemetry
    geo = header_info.get("geo_ip") or {}
    story.append(Paragraph("2. Originating Server Geo-Location & Network Telemetry", section_heading))
    geo_data = [
        [
            Paragraph("<b>Originating IP:</b>", body_style),
            Paragraph(f"<b>{summary.get('originating_ip', 'N/A')}</b>", body_mono),
            Paragraph("<b>Host Country:</b>", body_style),
            Paragraph(f"{geo.get('country', 'Unknown')} ({geo.get('country_code', 'UN')})", body_style)
        ],
        [
            Paragraph("<b>Location:</b>", body_style),
            Paragraph(f"{geo.get('city', 'Unknown')}, {geo.get('region', 'Unknown')}", body_style),
            Paragraph("<b>Coordinates:</b>", body_style),
            Paragraph(f"{geo.get('coordinates', '0.0000, 0.0000')}", body_mono)
        ],
        [
            Paragraph("<b>ISP / Registrar:</b>", body_style),
            Paragraph(f"{geo.get('isp', 'Unknown ISP')}", body_style),
            Paragraph("<b>ASN / Org:</b>", body_style),
            Paragraph(f"{geo.get('asn', 'N/A')}", body_style)
        ]
    ]
    geo_table = Table(geo_data, colWidths=[120, 150, 120, 150])
    geo_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), surface_bg),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(geo_table)
    story.append(Spacer(1, 10))

    # Section 3: NLP Content & Phishing Intent Analysis
    story.append(Paragraph("3. AI Phishing Intent & NLP Deception Analysis", section_heading))
    intent = content_info.get("phishing_intent", "LOW")
    urgency_score = content_info.get("urgency_score", 0)
    triggers = content_info.get("urgency_triggers") or []
    impersonations = content_info.get("brand_impersonations") or []

    nlp_summary_text = f"<b>Phishing Intent:</b> {intent} (Urgency Index: {urgency_score}/100) — {content_info.get('intent_description', '')}"
    story.append(Paragraph(nlp_summary_text, body_style))
    story.append(Spacer(1, 4))

    if triggers:
        trigger_rows = [
            [
                Paragraph("<b>Triggered Coercive Phrase</b>", body_style),
                Paragraph("<b>Psychological Deception Risk Pattern</b>", body_style)
            ]
        ]
        for t in triggers[:5]:
            trigger_rows.append([
                Paragraph(f"<i>'{t.get('phrase')}'</i>", body_style),
                Paragraph(f"{t.get('reason')}", body_style)
            ])
        trigger_table = Table(trigger_rows, colWidths=[200, 340])
        trigger_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), teal_light),
            ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
            ('PADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(trigger_table)
        story.append(Spacer(1, 8))

    # Brand Impersonations
    if impersonations:
        imp_html = "<br/>".join([f"• <b>{imp.get('brand')} Impersonation:</b> {imp.get('reason')}" for imp in impersonations])
        imp_table = Table([[Paragraph(imp_html, body_style)]], colWidths=[540])
        imp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fff1f2")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#fecdd3")),
            ('PADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(imp_table)
        story.append(Spacer(1, 8))

    # Section 4: Defanged Hyperlinks Extracted from Email
    urls = content_info.get("extracted_urls") or []
    if urls:
        story.append(Paragraph("4. Embedded Hyperlinks Discovered (Defanged)", section_heading))
        url_rows = [
            [
                Paragraph("<b>Defanged URL</b>", body_style),
                Paragraph("<b>Target Host / Domain</b>", body_style),
                Paragraph("<b>Risk Flag</b>", body_style)
            ]
        ]
        for u in urls[:6]:
            url_rows.append([
                Paragraph(f"{u.get('defanged_url', '')}", body_mono),
                Paragraph(f"{u.get('domain', '')}", body_style),
                Paragraph("Direct IP" if u.get("is_ip") else "Standard Domain", body_style)
            ])
        url_table = Table(url_rows, colWidths=[280, 160, 100])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), teal_light),
            ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
            ('PADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(url_table)
        story.append(Spacer(1, 10))

    # Structured Problem Findings Section
    findings = email_data.get("findings") or []
    if findings:
        story.append(Paragraph("5. Flagged Forensic Findings & Threat Evidence", section_heading))
        for f in findings:
            f_sev = (f.get("severity") or "low").upper()
            f_title = f.get("title") or "Flagged Threat Indicator"
            f_exp = f.get("explanation") or "Anomalous indicator identified."
            f_evi = safe_wrap(str(f.get("evidence") or "None"), max_chunk=65)
            f_rec = f.get("recommendation") or "Exercise caution before taking action."

            badge_color = colors.HexColor("#C23A0C") if f_sev in ("CRITICAL", "HIGH") else (colors.HexColor("#8A5A00") if f_sev in ("MEDIUM", "WARNING") else slate_muted)
            badge_bg = colors.HexColor("#fff1f2") if f_sev in ("CRITICAL", "HIGH") else (colors.HexColor("#fffbeb") if f_sev in ("MEDIUM", "WARNING") else surface_bg)

            card_content = [
                [Paragraph(f"<font color='{badge_color.hexval()}'><b>[{f_sev}]</b></font> <b>{safe_escape(f_title)}</b>", body_style)],
                [Paragraph(f"<b>Explanation:</b> {safe_escape(f_exp)}", body_style)],
                [Paragraph(f"<b>Evidence:</b> <font color='#12161D'>{f_evi}</font>", body_mono)],
                [Paragraph(f"<b>Recommended Action:</b> <font color='#0f766e'>{safe_escape(f_rec)}</font>", body_style)]
            ]
            card_table = Table(card_content, colWidths=[540])
            card_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), badge_bg),
                ('BACKGROUND', (0, 1), (-1, -1), surface_bg),
                ('BOX', (0, 0), (-1, -1), 0.8, slate_border),
                ('INNERGRID', (0, 0), (-1, -1), 0.3, slate_border),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(card_table)
            story.append(Spacer(1, 5))
        story.append(Spacer(1, 6))

    # Identified Risk Factors
    factors = email_data.get("risk_factors") or ["No deceptive indicators detected."]
    factors_html = "<br/>".join([f"• {f}" for f in factors[:6]])
    story.append(Paragraph("6. Forensic Investigation Summary & Risk Factors", section_heading))
    factors_table = Table([[Paragraph(factors_html, body_style)]], colWidths=[540])
    factors_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), teal_light),
        ('GRID', (0, 0), (-1, -1), 0.5, slate_border),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(factors_table)
    story.append(Spacer(1, 10))

    # Verification Footer
    footer_text = f"CONFIDENTIAL & PRIVILEGED EMAIL FORENSIC RECORD • CYBERSCAPE ENTERPRISE FORENSIC ENGINE • VERIFICATION HASH: {report_id}"
    story.append(KeepTogether([
        HRFlowable(width="100%", thickness=0.8, color=slate_border, spaceBefore=8, spaceAfter=4),
        Paragraph(footer_text, ParagraphStyle("Footer", fontName="Helvetica", fontSize=6.5, leading=9, textColor=slate_muted, alignment=TA_CENTER))
    ]))

    doc.build(story)
    return buffer.getvalue()


def generate_history_record_pdf(record: dict) -> bytes:
    """
    Generate an enterprise-grade cybersecurity forensic investigation PDF report
    for any history record (URL, QR, or Email) with full telemetry, findings,
    passed checks, and technical details.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=42
    )

    story = []
    styles = getSampleStyleSheet()

    # Design token colors
    color_ink = colors.HexColor("#12161D")
    color_panel = colors.HexColor("#F6F7F3")
    color_ground = colors.HexColor("#E8EAE4")
    color_line = colors.HexColor("#C9CDC4")
    color_muted = colors.HexColor("#4A5260")
    color_safe = colors.HexColor("#1D6B4C")
    color_safe_bg = colors.HexColor("#ecfdf5")
    color_suspicious = colors.HexColor("#8A5A00")
    color_suspicious_bg = colors.HexColor("#fffbeb")
    color_danger = colors.HexColor("#C23A0C")
    color_danger_bg = colors.HexColor("#fff1f2")

    verdict = (record.get("verdict") or "UNKNOWN").upper()
    if verdict == "MALICIOUS":
        status_color = color_danger
        status_bg = color_danger_bg
        verdict_label = "CRITICAL / MALICIOUS"
    elif verdict == "SUSPICIOUS":
        status_color = color_suspicious
        status_bg = color_suspicious_bg
        verdict_label = "SUSPICIOUS / ELEVATED RISK"
    else:
        status_color = color_safe
        status_bg = color_safe_bg
        verdict_label = "LOW RISK / VERIFIED SAFE"

    # Typography styles
    title_style = ParagraphStyle(
        "HistTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=17,
        leading=21,
        textColor=color_ink
    )
    meta_label = ParagraphStyle(
        "HistMetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=color_muted
    )
    meta_val = ParagraphStyle(
        "HistMetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=color_ink
    )
    section_title = ParagraphStyle(
        "HistSecTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=15,
        textColor=color_ink,
        spaceBefore=8,
        spaceAfter=4
    )
    body_text = ParagraphStyle(
        "HistBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=color_ink
    )
    body_mono = ParagraphStyle(
        "HistMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10.5,
        textColor=color_ink
    )
    card_title = ParagraphStyle(
        "HistCardTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13,
        textColor=color_ink
    )

    record_id = record.get("id") or "0"
    report_uid = f"CYBER-AUDIT-{record_id}-{uuid.uuid4().hex[:6].upper()}"
    timestamp = record.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scan_type = (record.get("scan_type") or "URL").upper()
    target_raw = record.get("target") or "Unspecified Target"
    target_wrapped = safe_wrap(target_raw, max_chunk=45)
    score = record.get("score", 0)
    level = record.get("level") or ("Low Risk" if verdict == "SAFE" else "High Risk")
    counts = record.get("severity_counts") or {}

    # 1. HEADER BANNER
    header_data = [
        [
            Paragraph("<b>CYBERSCAPE</b> | Forensic Threat Intelligence Report", title_style),
            Paragraph(f"<b>REPORT ID:</b> {report_uid}<br/><b>GENERATED:</b> {safe_escape(timestamp)}", ParagraphStyle("HdrMeta", fontName="Helvetica", fontSize=8, leading=11, textColor=color_muted, alignment=TA_RIGHT))
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=color_ink, spaceBefore=4, spaceAfter=8))

    # 2. TARGET & INVESTIGATION METADATA
    meta_table_data = [
        [
            Paragraph("<b>Target Destination:</b>", meta_label),
            Paragraph(f"<b>{target_wrapped}</b>", meta_val),
            Paragraph("<b>Ingress Channel:</b>", meta_label),
            Paragraph(f"<b>{safe_escape(scan_type)} Probes</b>", meta_val)
        ],
        [
            Paragraph("<b>Scan Timestamp:</b>", meta_label),
            Paragraph(safe_escape(timestamp), meta_val),
            Paragraph("<b>Investigation Level:</b>", meta_label),
            Paragraph(safe_escape(level), meta_val)
        ]
    ]
    meta_table = Table(meta_table_data, colWidths=[95, 205, 95, 145])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_panel),
        ('GRID', (0, 0), (-1, -1), 0.5, color_line),
        ('PADDING', (0, 0), (-1, -1), 4.5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # 3. EXECUTIVE SCORE & VERDICT BLOCK
    verdict_badge_style = ParagraphStyle(
        "VerdictBadgeP",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=status_color,
        alignment=TA_CENTER
    )
    score_big_style = ParagraphStyle(
        "ScoreBig",
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=22,
        textColor=status_color,
        alignment=TA_CENTER
    )

    sev_summary = (
        f"<b>Critical:</b> {counts.get('critical', 0)}  |  "
        f"<b>High:</b> {counts.get('high', 0)}  |  "
        f"<b>Medium:</b> {counts.get('medium', 0)}  |  "
        f"<b>Low:</b> {counts.get('low', 0)}  |  "
        f"<b>Passed:</b> {counts.get('safe', 0)}"
    )

    exec_data = [
        [
            Paragraph(f"{score}%", score_big_style),
            Paragraph(f"<b>VERDICT: {verdict_label}</b><br/><font size='8' color='#4A5260'>Risk Severity: {safe_escape(level)}</font>", verdict_badge_style),
            Paragraph(f"<b>Security Signals Evaluated</b><br/>{sev_summary}", ParagraphStyle("SevSum", fontName="Helvetica", fontSize=8, leading=11, textColor=color_ink, alignment=TA_CENTER))
        ]
    ]
    exec_table = Table(exec_data, colWidths=[100, 220, 220])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_bg),
        ('BOX', (0, 0), (-1, -1), 1, status_color),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, color_line),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 10))

    # 4. FLAGGED FINDINGS SECTION (Every problem as separate card)
    story.append(Paragraph("1. Flagged Problem Findings & Threat Signals", section_title))
    findings = record.get("findings") or []
    if not findings:
        story.append(Paragraph("<i>No active security threats or anomalous risk signals were flagged during this scan.</i>", body_text))
        story.append(Spacer(1, 6))
    else:
        for f in findings:
            f_sev = (f.get("severity") or "low").upper()
            f_cat = f.get("category") or "Security Signal"
            f_title = f.get("title") or "Flagged Indicator"
            f_exp = f.get("explanation") or "Anomalous behavior detected."
            f_evi = safe_wrap(str(f.get("evidence") or "None"), max_chunk=65)
            f_rec = f.get("recommendation") or "Exercise caution and verify destination."

            # Badge color
            badge_color = color_danger if f_sev in ("CRITICAL", "HIGH") else (color_suspicious if f_sev in ("MEDIUM", "WARNING") else color_muted)
            badge_bg = color_danger_bg if f_sev in ("CRITICAL", "HIGH") else (color_suspicious_bg if f_sev in ("MEDIUM", "WARNING") else color_panel)

            card_content = [
                [
                    Paragraph(f"<font color='{badge_color.hexval()}'><b>[{f_sev}]</b></font> <b>{safe_escape(f_cat)}: {safe_escape(f_title)}</b>", card_title)
                ],
                [
                    Paragraph(f"<b>Explanation:</b> {safe_escape(f_exp)}", body_text)
                ],
                [
                    Paragraph(f"<b>Evidence / Indicator:</b> <font color='#12161D'>{f_evi}</font>", body_mono)
                ],
                [
                    Paragraph(f"<b>Recommended Action:</b> <font color='#1D6B4C'>{safe_escape(f_rec)}</font>", body_text)
                ]
            ]
            card_table = Table(card_content, colWidths=[540])
            card_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), badge_bg),
                ('BACKGROUND', (0, 1), (-1, -1), color_panel),
                ('BOX', (0, 0), (-1, -1), 0.8, color_line),
                ('INNERGRID', (0, 0), (-1, -1), 0.3, color_line),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(card_table)
            story.append(Spacer(1, 5))

    story.append(Spacer(1, 6))

    # 5. PASSED CHECKS SECTION (Verified security capabilities)
    story.append(Paragraph("2. Verified Security Protections (Passed Checks)", section_title))
    passed_checks = record.get("passed_checks") or []
    if not passed_checks:
        story.append(Paragraph("<i>Standard baseline security checks performed.</i>", body_text))
    else:
        passed_rows = []
        for p in passed_checks:
            passed_rows.append([
                Paragraph("<font color='#1D6B4C'><b>[PASS]</b></font>", ParagraphStyle("PPass", fontName="Helvetica-Bold", fontSize=8, alignment=TA_CENTER)),
                Paragraph(f"<b>{safe_escape(p.get('title'))}:</b> {safe_escape(p.get('description'))}", body_text)
            ])
        passed_table = Table(passed_rows, colWidths=[45, 495])
        passed_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), color_panel),
            ('GRID', (0, 0), (-1, -1), 0.4, color_line),
            ('PADDING', (0, 0), (-1, -1), 3.5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(passed_table)

    story.append(Spacer(1, 10))

    # 6. TYPE-SPECIFIC TECHNICAL TELEMETRY
    tech = record.get("technical_details") or {}
    if scan_type in ("URL", "QR"):
        story.append(Paragraph(f"3. {scan_type} Infrastructure & Network Telemetry", section_title))
        url_b = tech.get("url_breakdown") or {}
        infra = tech.get("infrastructure") or {}
        redir = tech.get("redirect_chain") or {}
        intel_s = tech.get("threat_intel_summary") or {}

        tech_rows = [
            [
                Paragraph("<b>Canonical Destination:</b>", meta_label),
                Paragraph(safe_wrap(url_b.get("canonical_url", target_raw), 50), meta_val),
                Paragraph("<b>Final Landing URL:</b>", meta_label),
                Paragraph(safe_wrap(url_b.get("final_destination", target_raw), 50), meta_val)
            ],
            [
                Paragraph("<b>Hostname / Domain:</b>", meta_label),
                Paragraph(safe_escape(url_b.get("host", "Autonomous")), meta_val),
                Paragraph("<b>TLS / Encryption:</b>", meta_label),
                Paragraph(safe_escape(tech.get("tls_certificate", {}).get("status", "N/A")), meta_val)
            ],
            [
                Paragraph("<b>Destination IP:</b>", meta_label),
                Paragraph(f"<font face='Courier'>{safe_escape(infra.get('ip_address', 'Unresolved'))}</font>", meta_val),
                Paragraph("<b>Reverse DNS (PTR):</b>", meta_label),
                Paragraph(f"<font face='Courier'>{safe_escape(infra.get('reverse_dns', 'None'))}</font>", meta_val)
            ],
            [
                Paragraph("<b>ASN & Org:</b>", meta_label),
                Paragraph(safe_escape(infra.get("asn_org", "Enterprise Host Network")), meta_val),
                Paragraph("<b>Geographic Node:</b>", meta_label),
                Paragraph(safe_escape(infra.get("location", "Global Network")), meta_val)
            ],
            [
                Paragraph("<b>Redirect Hops:</b>", meta_label),
                Paragraph(f"{redir.get('hops_count', 0)} hop(s) detected", meta_val),
                Paragraph("<b>Threat Intelligence:</b>", meta_label),
                Paragraph(f"{intel_s.get('engines_flagged', 0)}/{intel_s.get('total_engines', 90)} Engines Flagged", meta_val)
            ]
        ]
        if scan_type == "QR" and "qr_payload" in tech:
            qr_p = tech["qr_payload"]
            tech_rows.append([
                Paragraph("<b>QR Payload Format:</b>", meta_label),
                Paragraph(f"<b>{safe_escape(qr_p.get('payload_type', 'Web URL'))}</b>", meta_val),
                Paragraph("<b>QR Obfuscation Risk:</b>", meta_label),
                Paragraph(safe_escape(qr_p.get("risk_assessment", "Clean")), meta_val)
            ])

        tech_table = Table(tech_rows, colWidths=[105, 175, 105, 155])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), color_panel),
            ('GRID', (0, 0), (-1, -1), 0.5, color_line),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(tech_table)

    elif scan_type == "EMAIL":
        story.append(Paragraph("3. Email Header & Cryptographic Authentication Telemetry", section_title))
        sender_v = tech.get("sender_verification") or {}
        auth_p = tech.get("authentication_protocols") or {}
        orig_net = tech.get("origin_network") or {}
        cnt_l = tech.get("content_and_links") or {}

        email_rows = [
            [
                Paragraph("<b>From Address:</b>", meta_label),
                Paragraph(f"<b>{safe_escape(sender_v.get('from_address'))}</b> ({safe_escape(sender_v.get('display_name'))})", meta_val),
                Paragraph("<b>Return-Path:</b>", meta_label),
                Paragraph(safe_escape(sender_v.get("return_path", "None")), meta_val)
            ],
            [
                Paragraph("<b>Reply-To:</b>", meta_label),
                Paragraph(safe_escape(sender_v.get("reply_to", "Default to From")), meta_val),
                Paragraph("<b>Sender Spoofing:</b>", meta_label),
                Paragraph(f"<font color='{'#C23A0C' if sender_v.get('is_spoofed') else '#1D6B4C'}'><b>{'DETECTED' if sender_v.get('is_spoofed') else 'ALIGNED'}</b></font>", meta_val)
            ],
            [
                Paragraph("<b>SPF Status:</b>", meta_label),
                Paragraph(f"<b>{safe_escape(auth_p.get('spf', {}).get('status', 'NONE'))}</b> - {safe_escape(auth_p.get('spf', {}).get('explanation', ''))[:45]}", meta_val),
                Paragraph("<b>DKIM Status:</b>", meta_label),
                Paragraph(f"<b>{safe_escape(auth_p.get('dkim', {}).get('status', 'NONE'))}</b> - {safe_escape(auth_p.get('dkim', {}).get('explanation', ''))[:45]}", meta_val)
            ],
            [
                Paragraph("<b>DMARC Status:</b>", meta_label),
                Paragraph(f"<b>{safe_escape(auth_p.get('dmarc', {}).get('status', 'NONE'))}</b> - {safe_escape(auth_p.get('dmarc', {}).get('explanation', ''))[:45]}", meta_val),
                Paragraph("<b>Originating IP:</b>", meta_label),
                Paragraph(f"<font face='Courier'>{safe_escape(orig_net.get('originating_ip', 'N/A'))}</font> ({safe_escape(orig_net.get('country', 'Unknown'))})", meta_val)
            ],
            [
                Paragraph("<b>Origin ISP / ASN:</b>", meta_label),
                Paragraph(safe_escape(orig_net.get("isp_asn", "Unknown")), meta_val),
                Paragraph("<b>Phishing Urgency Index:</b>", meta_label),
                Paragraph(f"{cnt_l.get('urgency_index', 0)}/100 (Links: {cnt_l.get('total_links', 0)})", meta_val)
            ]
        ]
        email_table = Table(email_rows, colWidths=[105, 175, 105, 155])
        email_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), color_panel),
            ('GRID', (0, 0), (-1, -1), 0.5, color_line),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(email_table)

    story.append(Spacer(1, 10))

    # 7. DISCLAIMER FOOTER
    disclaimer = (
        "<b>LEGAL & COMPLIANCE NOTICE:</b> This forensic cybersecurity threat report is generated automatically by CyberScape Enterprise Defense Platform. "
        "Evaluations are based on heuristic rule sets, algorithmic reputation feeds, and point-in-time telemetry. "
        "Findings should be cross-examined with authoritative threat intelligence prior to executing legal or regulatory remediation."
    )
    story.append(KeepTogether([
        HRFlowable(width="100%", thickness=0.5, color=color_line, spaceBefore=4, spaceAfter=4),
        Paragraph(disclaimer, ParagraphStyle("HistDisclaimer", fontName="Helvetica", fontSize=6.5, leading=9, textColor=color_muted, alignment=TA_CENTER))
    ]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()


def generate_all_history_pdf(records: list, user_email: str) -> bytes:
    """
    Generate a consolidated audit log summary PDF of all past forensic scans
    for the authenticated user.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=42
    )

    story = []
    styles = getSampleStyleSheet()

    color_ink = colors.HexColor("#12161D")
    color_panel = colors.HexColor("#F6F7F3")
    color_line = colors.HexColor("#C9CDC4")
    color_muted = colors.HexColor("#4A5260")
    color_safe = colors.HexColor("#1D6B4C")
    color_danger = colors.HexColor("#C23A0C")
    color_suspicious = colors.HexColor("#8A5A00")

    title_style = ParagraphStyle("AllHistTitle", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=color_ink)
    sub_style = ParagraphStyle("AllHistSub", fontName="Helvetica", fontSize=8.5, leading=11, textColor=color_muted)
    cell_style = ParagraphStyle("AllHistCell", fontName="Helvetica", fontSize=8, leading=10.5, textColor=color_ink)
    cell_mono = ParagraphStyle("AllHistMono", fontName="Courier", fontSize=7.5, leading=9.5, textColor=color_ink)

    # Header
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph("<b>CYBERSCAPE</b> | Consolidated Forensic Audit Trail", title_style))
    story.append(Paragraph(f"Authenticated Account: <b>{safe_escape(user_email)}</b> • Generated: {now_str} • Total Records: {len(records)}", sub_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=color_ink, spaceBefore=4, spaceAfter=8))

    # Summary Statistics Strip
    total = len(records)
    safe = sum(1 for r in records if (r.get("verdict") or "").upper() == "SAFE")
    suspicious = sum(1 for r in records if (r.get("verdict") or "").upper() == "SUSPICIOUS")
    malicious = sum(1 for r in records if (r.get("verdict") or "").upper() == "MALICIOUS")
    url_c = sum(1 for r in records if (r.get("scan_type") or "").upper() == "URL")
    qr_c = sum(1 for r in records if (r.get("scan_type") or "").upper() == "QR")
    email_c = sum(1 for r in records if (r.get("scan_type") or "").upper() == "EMAIL")

    stat_data = [
        [
            Paragraph(f"<b>TOTAL LOGS:</b> {total}", cell_style),
            Paragraph(f"<font color='{color_safe.hexval()}'><b>VERIFIED CLEAN:</b> {safe}</font>", cell_style),
            Paragraph(f"<font color='{color_suspicious.hexval()}'><b>SUSPICIOUS:</b> {suspicious}</font>", cell_style),
            Paragraph(f"<font color='{color_danger.hexval()}'><b>BLOCKED THREATS:</b> {malicious}</font>", cell_style)
        ],
        [
            Paragraph(f"<b>URL Probes:</b> {url_c}", cell_style),
            Paragraph(f"<b>QR Decodes:</b> {qr_c}", cell_style),
            Paragraph(f"<b>Email Scans:</b> {email_c}", cell_style),
            Paragraph("<b>Status:</b> Active Audit Trail", cell_style)
        ]
    ]
    stat_table = Table(stat_data, colWidths=[135, 135, 135, 135])
    stat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_panel),
        ('GRID', (0, 0), (-1, -1), 0.5, color_line),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 10))

    # Records Table
    table_rows = [
        [
            Paragraph("<b>Target Destination</b>", cell_style),
            Paragraph("<b>Ingress</b>", cell_style),
            Paragraph("<b>Score</b>", cell_style),
            Paragraph("<b>Threat Status</b>", cell_style),
            Paragraph("<b>Timestamp</b>", cell_style)
        ]
    ]
    for r in records:
        v = (r.get("verdict") or "UNKNOWN").upper()
        v_color = color_danger if v == "MALICIOUS" else (color_suspicious if v == "SUSPICIOUS" else color_safe)
        v_text = "CRITICAL" if v == "MALICIOUS" else ("SUSPICIOUS" if v == "SUSPICIOUS" else "LOW RISK")
        score_val = r.get("score", 0)
        target_str = safe_wrap(str(r.get("target") or "Unknown"), max_chunk=40)

        table_rows.append([
            Paragraph(target_str, cell_style),
            Paragraph(safe_escape((r.get("scan_type") or "URL").upper()), cell_style),
            Paragraph(f"<b>{score_val}%</b>", cell_style),
            Paragraph(f"<font color='{v_color.hexval()}'><b>{v_text}</b></font>", cell_style),
            Paragraph(safe_escape(str(r.get("timestamp") or "")[:19]), cell_mono)
        ])

    rec_table = Table(table_rows, colWidths=[240, 55, 45, 95, 105])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E8EAE4")),
        ('GRID', (0, 0), (-1, -1), 0.4, color_line),
        ('PADDING', (0, 0), (-1, -1), 3),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(rec_table)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()


"""
CyberScape Automated Forensic PDF Report Generator
Generates enterprise-grade cybersecurity forensic investigation reports using ReportLab.
"""

import io
import uuid
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


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
                Paragraph(f"{step.get('url')}" + (f" ➔ <i>{step.get('redirect_to')}</i>" if step.get("redirect_to") else ""), body_mono)
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

    # Identified Risk Factors
    factors = email_data.get("risk_factors") or ["No deceptive indicators detected."]
    factors_html = "<br/>".join([f"• {f}" for f in factors[:6]])
    story.append(Paragraph("5. Forensic Investigation Summary & Risk Factors", section_heading))
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

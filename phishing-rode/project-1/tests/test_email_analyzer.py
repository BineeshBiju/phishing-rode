"""
Unit and Integration Tests for CyberScape AI Fake Email & Header Tracker
Tests:
- Header parsing and sender spoofing detection
- SPF, DKIM, and DMARC authentication validation
- Originating IP extraction and geo-telemetry
- NLP urgency and panic scam analysis
- Defanged URL extraction
- Brand impersonation alerts
- PDF report generation endpoint
"""

import pytest
from app import app
import email_analyzer
import report_generator


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_parse_spoofed_email_header():
    raw_header = (
        'From: "PayPal Support" <service@fake-account-update.xyz>\n'
        'Return-Path: <bounce@malicious-node.ru>\n'
        'Received: from mail.malicious-node.ru ([185.220.101.5])\n'
        'Received-SPF: fail\n'
        'Subject: Account Suspended'
    )
    res = email_analyzer.parse_email_headers(raw_header)
    assert res["has_header"] is True
    assert res["is_spoofed"] is True
    assert res["from_domain"] == "fake-account-update.xyz"
    assert res["return_domain"] == "malicious-node.ru"
    assert res["originating_ip"] == "185.220.101.5"
    assert res["authentication"]["spf"] == "FAIL"
    assert "FAILED" in res["authentication"]["verdict"]


def test_originating_ip_extraction():
    received = [
        "from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mx.google.com",
        "from [192.168.1.10] (client.isp.com [185.220.101.99]) by relay.net"
    ]
    ip = email_analyzer.extract_ip_from_header(received)
    assert ip == "185.220.101.99"


def test_nlp_urgency_and_brand_impersonation():
    content = (
        "Dear customer, your PayPal account will be suspended within 24 hours. "
        "Immediate verification required. Click here to confirm: http://192.168.1.1/login"
    )
    res = email_analyzer.analyze_email_content(
        subject_text="Urgent Security Alert",
        body_text=content,
        sender_domain="suspicious-domain.xyz"
    )
    assert res["has_content"] is True
    assert res["phishing_intent"] == "HIGH"
    assert len(res["urgency_triggers"]) >= 2
    assert any(imp["brand"] == "Paypal" for imp in res["brand_impersonations"])
    assert len(res["extracted_urls"]) == 1
    assert "hxxp" in res["extracted_urls"][0]["defanged_url"]


def test_full_email_investigation_malicious():
    header = (
        'From: "PayPal Notice" <service@update-paypal.xyz>\n'
        'Return-Path: <bounce@offshore.ru>\n'
        'Received-SPF: fail\n'
        'Subject: Account Suspended in 24 Hours'
    )
    body = "Immediate action required. Verify your password now at http://185.220.101.5/login"
    res = email_analyzer.full_email_investigation(header, body)
    assert res["verdict"] == "MALICIOUS"
    assert res["score"] >= 70
    assert res["summary"]["is_spoofed"] is True
    assert res["summary"]["phishing_intent"] == "HIGH"


def test_api_analyze_email(client):
    response = client.post(
        "/api/analyze-email",
        json={
            "header_text": "From: test@example.com\nReturn-Path: test@example.com\nReceived-SPF: pass",
            "content_text": "Hello, thank you for your regular order. Receipt attached."
        }
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "score" in data
    assert "verdict" in data
    assert data["verdict"] in {"SAFE", "SUSPICIOUS", "MALICIOUS"}
    assert "summary" in data


def test_api_generate_email_report_pdf(client):
    response = client.post(
        "/api/generate-email-report",
        json={
            "score": 90,
            "verdict": "MALICIOUS",
            "level": "High Risk Fake Email",
            "risk_factors": ["Domain mismatch", "SPF failure"],
            "header_analysis": {
                "from_header": "support@fake.com",
                "from_addr": "support@fake.com",
                "subject": "Phishing Test",
                "geo_ip": {"country": "Netherlands", "country_code": "NL"}
            },
            "content_analysis": {
                "phishing_intent": "HIGH",
                "urgency_score": 80,
                "urgency_triggers": [{"phrase": "suspended in 24 hours", "reason": "Panic"}]
            },
            "summary": {
                "authentication": "FAILED (Spoofed Domain)",
                "originating_ip": "185.220.101.5"
            }
        }
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert response.data.startswith(b"%PDF")


def test_email_analyzer_page_layout_no_option_a_and_b(client):
    response = client.get("/email-analyzer")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Verify brand & module title
    assert "CYBERSPACE" in html
    assert "Fake Email & Header Threat Analyzer" in html

    # Verify Option A and Option B are completely removed
    assert "Option A" not in html
    assert "Option B" not in html
    assert "OPTION A" not in html
    assert "OPTION B" not in html

    # Verify core inputs and actions are present
    assert "headerInput" in html
    assert "contentInput" in html
    assert "analyzeEmailBtn" in html
    assert "Email Header & Sender Verification" in html
    assert "Email Text & Phishing Intent Analysis" in html
    assert "Spoofed PayPal" in html

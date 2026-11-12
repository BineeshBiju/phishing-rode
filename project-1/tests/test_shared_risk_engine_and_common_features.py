"""
Tests for CyberScape Shared Risk Engine, Structured Findings, History DB persistence,
Rate Limiting, and Input Validation across URL Scanner, QR Scanner, and Email Analyzer.
"""

import io
import json
import pytest
from app import app, get_db
from backend.services.scoring import evaluate_risk, verdict_from_score, compute_confidence
from backend.services.orchestrator import scan_url
from backend.services.qr_analyzer import scan_qr_payload
import email_analyzer
from backend.services.rate_limiter import SlidingWindowRateLimiter, limiter


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "admin@cyberscape.test"
            sess["name"] = "Admin"
        yield client


# =====================================================================
# 1. SHARED RISK ENGINE TESTS
# =====================================================================

def test_shared_risk_engine_verdicts_and_scoring():
    """Verify single shared risk engine produces score (0-100), verdict (Safe/Suspicious/Malicious), and confidence."""
    # Benign / Safe threshold
    safe_risk = evaluate_risk(10, scan_type="URL")
    assert safe_risk["score"] == 10
    assert safe_risk["status"] == "SAFE"
    assert safe_risk["verdict_title"] == "Safe"
    assert safe_risk["level"] == "Low Risk"
    assert 0 <= safe_risk["confidence"] <= 100

    # Suspicious threshold
    suspicious_risk = evaluate_risk(45, scan_type="QR", confidence=90)
    assert suspicious_risk["score"] == 45
    assert suspicious_risk["status"] == "SUSPICIOUS"
    assert suspicious_risk["verdict_title"] == "Suspicious"
    assert suspicious_risk["level"] == "Elevated Risk"
    assert suspicious_risk["confidence"] == 90

    # Malicious threshold
    malicious_risk = evaluate_risk(85, scan_type="EMAIL")
    assert malicious_risk["score"] == 85
    assert malicious_risk["status"] == "MALICIOUS"
    assert malicious_risk["verdict_title"] == "Malicious"
    assert malicious_risk["level"] == "High Risk"
    assert 0 <= malicious_risk["confidence"] <= 100


def test_confidence_computation_across_all_three_scanners():
    """Verify confidence calculation for URL, QR, and Email based on available feeds/records."""
    # URL Scanner confidence with all 4 feeds active
    url_sources = {
        "urlhaus": {"available": True},
        "safebrowsing": {"available": True},
        "virustotal": {"available": True},
        "openphish": {"available": True}
    }
    assert compute_confidence(url_sources, scan_type="URL") >= 95

    # QR Scanner non-URL confidence
    qr_sources = {"upi_protocol": {"available": True}, "payee_check": {"available": True}}
    assert compute_confidence(qr_sources, scan_type="QR") == 95

    # Email Scanner confidence with SPF, DKIM, DMARC, DNS
    email_sources = {
        "spf": {"available": True},
        "dkim": {"available": True},
        "dmarc": {"available": True},
        "dns": {"available": True}
    }
    assert compute_confidence(email_sources, scan_type="EMAIL") >= 90


# =====================================================================
# 2. STRUCTURED FINDINGS LIST & HISTORY DB PERSISTENCE TESTS
# =====================================================================

def test_url_scanner_returns_structured_findings():
    """Verify URL scanner returns findings with {title, severity, explanation, evidence}."""
    report = scan_url("https://en.wikipedia.org/wiki/Main_Page")
    assert "findings" in report
    assert isinstance(report["findings"], list)
    for f in report["findings"]:
        assert "title" in f
        assert "severity" in f
        assert "explanation" in f
        assert "evidence" in f


def test_qr_scanner_returns_structured_findings():
    """Verify QR scanner returns findings with {title, severity, explanation, evidence}."""
    # Test UPI payload
    upi_report = scan_qr_payload("upi://pay?pa=fake.electricity@okaxis&pn=Electricity%20Bill%20Refund&am=1500&cu=INR")
    assert "findings" in upi_report
    assert isinstance(upi_report["findings"], list)
    assert len(upi_report["findings"]) > 0
    for f in upi_report["findings"]:
        assert "title" in f
        assert "severity" in f
        assert "explanation" in f
        assert "evidence" in f


def test_email_analyzer_returns_structured_findings():
    """Verify Email analyzer returns findings with {title, severity, explanation, evidence}."""
    header = (
        'From: "PayPal Security" <support@paypal-urgent-update.xyz>\n'
        'Return-Path: <bounce@bad-node.ru>\n'
        'Subject: Account Alert\n\n'
    )
    body = "Dear customer, your PayPal account is restricted. Visit: http://192.168.1.1/login"
    email_report = email_analyzer.full_email_investigation(header, body)
    assert "findings" in email_report
    assert isinstance(email_report["findings"], list)
    assert len(email_report["findings"]) > 0
    for f in email_report["findings"]:
        assert "title" in f
        assert "severity" in f
        assert "explanation" in f
        assert "evidence" in f


def test_history_db_persists_full_findings_and_inspect_api(client):
    """Verify scans save the full findings list to DB and /api/history/<id> returns all of them."""
    # 1. Execute an email scan via API
    res = client.post("/analyze-email", json={
        "header": 'From: "Bank Support" <alert@fake-bank.top>\nReturn-Path: <bounce@mailer.ru>\nSubject: Action Required',
        "body": "Dear account holder, verify your credentials immediately: http://185.220.101.5/login"
    })
    assert res.status_code == 200
    data = res.get_json()
    assert "findings" in data
    assert len(data["findings"]) > 0

    # 2. Get last inserted record ID from DB
    with get_db() as conn:
        row = conn.execute("SELECT id, details_json FROM scan_logs ORDER BY id DESC LIMIT 1").fetchone()
        assert row is not None
        rec_id = row["id"]
        saved_details = json.loads(row["details_json"])
        assert "findings" in saved_details
        assert len(saved_details["findings"]) > 0

    # 3. Test /api/history/<id> endpoint returns findings with title, severity, explanation, evidence
    inspect_res = client.get(f"/api/history/{rec_id}")
    assert inspect_res.status_code == 200
    inspect_data = inspect_res.get_json()
    assert inspect_data["success"] is True
    record = inspect_data["record"]
    assert "findings" in record
    assert len(record["findings"]) > 0
    for f in record["findings"]:
        assert "title" in f
        assert "severity" in f
        assert "explanation" in f
        assert "evidence" in f

    # 4. Test PDF forensic report generation for this history record
    pdf_res = client.get(f"/history/{rec_id}/report.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["Content-Type"] == "application/pdf"
    assert pdf_res.data.startswith(b"%PDF")


# =====================================================================
# 3. RATE LIMITING TESTS
# =====================================================================

def test_sliding_window_rate_limiter_logic():
    """Verify sliding window rate limiter permits allowed requests and blocks exceeding bursts."""
    custom_limiter = SlidingWindowRateLimiter(default_limit=3, default_window=60)
    client_key = "192.168.1.100"

    # 1st request -> allowed
    allowed, retry_after = custom_limiter.is_allowed(client_key)
    assert allowed is True
    assert retry_after == 0

    # 2nd request -> allowed
    allowed, retry_after = custom_limiter.is_allowed(client_key)
    assert allowed is True

    # 3rd request -> allowed
    allowed, retry_after = custom_limiter.is_allowed(client_key)
    assert allowed is True

    # 4th request -> blocked with retry_after
    allowed, retry_after = custom_limiter.is_allowed(client_key)
    assert allowed is False
    assert retry_after > 0


# =====================================================================
# 4. INPUT VALIDATION & ERROR MESSAGES TESTS
# =====================================================================

def test_url_scanner_input_validation(client):
    """Verify input validation on /check-url."""
    # Empty URL
    res_empty = client.post("/check-url", json={"url": "   "})
    assert res_empty.status_code == 400
    assert "Please enter a URL" in res_empty.get_json()["error"]

    # Oversized URL (> 2048 chars)
    res_long = client.post("/check-url", json={"url": "https://example.com/" + "a" * 2100})
    assert res_long.status_code == 400
    assert "maximum supported length" in res_long.get_json()["error"]

    # Invalid scheme input returns structured INVALID scan
    res_js = client.post("/check-url", json={"url": "javascript:alert(1)"})
    assert res_js.status_code == 200
    assert res_js.get_json()["status"] == "INVALID"


def test_qr_scanner_input_validation(client):
    """Verify input validation on /qr-result and /decode-qr."""
    # Empty payload
    res_empty = client.post("/qr-result", json={"url": ""})
    assert res_empty.status_code == 400
    assert "No QR payload" in res_empty.get_json()["error"]

    # Oversized payload
    res_long = client.post("/qr-result", json={"url": "upi://pay?" + "x" * 4100})
    assert res_long.status_code == 400
    assert "maximum supported length" in res_long.get_json()["error"]

    # Empty decode file
    res_empty_file = client.post(
        "/decode-qr",
        data={"qr_file": (io.BytesIO(b""), "empty.png")},
        content_type="multipart/form-data"
    )
    assert res_empty_file.status_code == 400
    assert "empty" in res_empty_file.get_json()["error"].lower()


def test_email_analyzer_input_validation(client):
    """Verify input validation on /analyze-email."""
    # Empty inputs
    res_empty = client.post("/analyze-email", json={"header": "  ", "body": "  "})
    assert res_empty.status_code == 400
    assert "Please provide an email header" in res_empty.get_json()["error"]

    # Empty .eml file upload
    res_empty_eml = client.post(
        "/analyze-email",
        data={"eml_file": (io.BytesIO(b""), "empty.eml")},
        content_type="multipart/form-data"
    )
    assert res_empty_eml.status_code == 400
    assert "empty" in res_empty_eml.get_json()["error"].lower()

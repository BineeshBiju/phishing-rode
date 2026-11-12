"""
Integration tests for CyberScape Upgraded Production-Grade Features:
1. Live Threat Intelligence API integration & structured JSON output
2. Automatic QR threat pipeline integration & decode endpoints
3. AI Email Analyzer multi-track forensics (SPF/DKIM/DMARC, NLP urgency, spoofing)
4. Dashboard dynamic SQLite database logging & pagination API endpoints (/api/dashboard/stats, /api/dashboard/logs)
5. CORS and environment configuration
"""

import pytest
import json
from app import app, get_db


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_url_scanner_structured_json_and_telemetry(client):
    """Test URL Scanner returns structured JSON containing threat status, risk score, and telemetry details."""
    response = client.post(
        "/check-url",
        json={"url": "https://en.wikipedia.org/wiki/Phishing"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "url" in data
    assert "final_url" in data
    assert "score" in data
    assert "status" in data
    assert data["status"] in {"SAFE", "SUSPICIOUS", "MALICIOUS"}
    assert "ml_analysis" in data
    assert "threat_intel" in data
    assert "geo_ip" in data
    assert "redirect_chain" in data
    assert "reasons" in data

    # Verify threat intel engines
    ti = data["threat_intel"]
    assert "urlhaus" in ti
    assert "virustotal" in ti
    assert "safebrowsing" in ti
    assert "flagged_engines" in ti
    assert "total_engines" in ti


def test_qr_scanner_pipeline_integration(client):
    """Test that decoded QR destination passes directly into threat inspection pipeline."""
    response = client.post(
        "/qr-result",
        json={"url": "https://en.wikipedia.org/wiki/QR_code"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "QR"
    assert "score" in data
    assert "status" in data
    assert "geo_ip" in data
    assert "redirect_chain" in data


def test_email_analyzer_advanced_nlp_and_headers(client):
    """Test AI Email Analyzer parses headers, authenticates SPF/DKIM/DMARC, and detects NLP urgency."""
    test_header = (
        "From: \"Account Support\" <alert@fake-service.xyz>\n"
        "Return-Path: <bounce@unrelated-server.ru>\n"
        "Received-SPF: fail\n"
        "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n"
        "Received: from [185.220.101.5] by mx.google.com\n"
        "Subject: Urgent: Verify your password within 24 hours"
    )
    test_body = (
        "Immediate attention required: your account is suspended.\n"
        "Click here to verify: http://192.168.1.100/login"
    )
    response = client.post(
        "/analyze-email",
        json={"header_text": test_header, "content_text": test_body}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "score" in data
    assert "verdict" in data
    assert data["verdict"] in {"MALICIOUS", "SUSPICIOUS"}
    assert "header_analysis" in data
    assert "content_analysis" in data
    assert "summary" in data

    header_res = data["header_analysis"]
    assert header_res["is_spoofed"] is True
    assert header_res["authentication"]["spf"] == "FAIL"

    content_res = data["content_analysis"]
    assert content_res["phishing_intent"] in {"HIGH", "MEDIUM"}
    assert len(content_res["extracted_urls"]) >= 1


def test_dashboard_api_stats_endpoint(client):
    """Test live statistics API endpoint returns counts from SQLite database."""
    response = client.get("/api/dashboard/stats")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "total" in data
    assert "safe" in data
    assert "suspicious" in data
    assert "blocked" in data
    assert "url" in data
    assert "qr" in data
    assert data["total"] >= 0


def test_dashboard_api_logs_pagination_and_filter(client):
    """Test dynamic pagination and search filter API endpoint against SQLite database."""
    # Ensure at least one real URL scan exists
    client.post("/check-url", json={"url": "https://example.com/api-test-probe"})

    response = client.get("/api/dashboard/logs?page=1&per_page=10")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "logs" in data
    assert "total" in data
    assert "page" in data
    assert len(data["logs"]) <= 10
    assert data["page"] == 1

    # Filter by source=URL
    url_res = client.get("/api/dashboard/logs?source=URL")
    assert url_res.status_code == 200
    url_data = url_res.get_json()
    assert all(item["source"] == "URL" for item in url_data["logs"])


def test_dynamic_scan_persists_to_sqlite(client):
    """Test that scanning a URL dynamically inserts a record into SQLite scan_logs."""
    test_unique_url = "https://unique-test-scan-target.example.org"
    scan_res = client.post("/check-url", json={"url": test_unique_url})
    assert scan_res.status_code == 200

    with get_db() as conn:
        row = conn.execute("SELECT * FROM scan_logs WHERE target_url = ?", (test_unique_url,)).fetchone()
        assert row is not None
        assert row["target_url"] == test_unique_url
        assert row["source"] == "URL"


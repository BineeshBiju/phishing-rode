"""
Integration & Unit Tests for CyberScape History Inspect API and ReportLab PDF Generation
Tests:
- GET /api/history/<id> structured forensic payload (URL, QR, Email, Legacy)
- Strict user ownership access control for inspection and PDF export (403 Forbidden)
- GET /history/<id>/report.pdf generation using ReportLab NumberedCanvas
- GET /history/export-all.pdf multi-record summary export
- Dashboard stats aggregation (total = url + qr + email)
- Dashboard logs pagination and email source filtering
"""

import json
from datetime import datetime
import pytest
from app import app, get_db


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def create_test_user_and_login(client, email="analyst_test@cyberscape.test", name="Security Analyst"):
    """Helper to simulate an authenticated user session in Flask test client and ensure clean state."""
    with get_db() as conn:
        conn.execute("DELETE FROM scan_logs WHERE user_email = ?", (email,))
    with client.session_transaction() as sess:
        sess["user"] = email
        sess["name"] = name


def insert_scan_log(user_email, target_url, score, status, level, source, details_dict=None):
    """Helper to insert a record into SQLite scan_logs table."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_logs (target_url, score, status, level, source, time, details_json, user_email, domain, registrar)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_url,
                score,
                status,
                level,
                source,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps(details_dict) if details_dict else None,
                user_email,
                "example.test",
                "Test Cloud Network"
            )
        )
        return cursor.lastrowid


def test_history_inspect_api_url_record(client):
    """Verify GET /api/history/<id> returns structured telemetry for a URL probe."""
    user = "alice@cyberscape.test"
    create_test_user_and_login(client, email=user)

    url_details = {
        "url": "https://secure-login.test/auth",
        "domain": "secure-login.test",
        "status": "MALICIOUS",
        "score": 88,
        "signals": [
            {
                "id": "urlhaus_blacklist",
                "severity": "high",
                "title": "URLhaus Blacklist Match",
                "explanation": "Flagged as active malware distribution host."
            }
        ],
        "sources_checked": {
            "urlhaus": {"status": "OK"},
            "virustotal": {"status": "OK"}
        },
        "geo_ip": {
            "ip": "198.51.100.25",
            "city": "Frankfurt",
            "country": "Germany",
            "country_code": "DE",
            "asn": "AS20940",
            "org": "Akamai Technologies"
        }
    }
    rec_id = insert_scan_log(user, "https://secure-login.test/auth", 88, "MALICIOUS", "High Risk", "URL", url_details)

    resp = client.get(f"/api/history/{rec_id}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    rec = data["record"]
    assert rec["id"] == rec_id
    assert rec["scan_type"] == "URL"
    assert rec["score"] == 88
    assert rec["verdict"] == "MALICIOUS"
    assert rec["limited_data"] is False
    assert len(rec["findings"]) >= 1
    assert rec["findings"][0]["severity"] == "high"
    assert rec["findings"][0]["recommendation"] != ""
    assert len(rec["passed_checks"]) >= 1
    assert "url_breakdown" in rec["technical_details"]
    assert rec["technical_details"]["infrastructure"]["ip_address"] == "198.51.100.25"


def test_history_inspect_api_email_record(client):
    """Verify GET /api/history/<id> returns structured telemetry for an Email scan."""
    user = "bob@cyberscape.test"
    create_test_user_and_login(client, email=user)

    email_details = {
        "target": "security@paypal-spoof.xyz — Urgent Verification",
        "scan_type": "EMAIL",
        "source": "EMAIL",
        "score": 95,
        "verdict": "MALICIOUS",
        "sender_check": {
            "from_addr": "security@paypal-spoof.xyz",
            "from_domain": "paypal-spoof.xyz",
            "is_spoofed": True,
            "return_path": "bounce@evil.ru"
        },
        "auth_results": {
            "spf": {"status": "FAIL", "explanation": "Sender IP not in SPF."},
            "dkim": {"status": "FAIL", "explanation": "No DKIM signature."},
            "dmarc": {"status": "FAIL", "explanation": "DMARC policy failed."}
        },
        "origin_ip": {
            "ip": "185.220.101.5",
            "country": "Russia",
            "city": "Moscow",
            "asn": "AS49981"
        },
        "content_findings": {
            "urgency_score": 85,
            "ceo_fraud_detected": False,
            "phishing_intent": "HIGH"
        },
        "findings": [
            {
                "category": "Sender Spoofing",
                "severity": "high",
                "title": "Lookalike Brand Mimicry",
                "explanation": "Domain paypal-spoof.xyz mimics legitimate brand PayPal."
            }
        ]
    }
    rec_id = insert_scan_log(user, "security@paypal-spoof.xyz — Urgent Verification", 95, "MALICIOUS", "High Risk", "EMAIL", email_details)

    resp = client.get(f"/api/history/{rec_id}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    rec = data["record"]
    assert rec["scan_type"] == "EMAIL"
    assert rec["score"] == 95
    assert "sender_verification" in rec["technical_details"]
    assert rec["technical_details"]["sender_verification"]["is_spoofed"] is True
    assert rec["technical_details"]["authentication_protocols"]["spf"]["status"] == "FAIL"
    assert rec["technical_details"]["origin_network"]["originating_ip"] == "185.220.101.5"


def test_history_inspect_api_legacy_record(client):
    """Verify legacy records with missing details_json return limited_data: True gracefully."""
    user = "carol@cyberscape.test"
    create_test_user_and_login(client, email=user)

    rec_id = insert_scan_log(user, "https://legacy-site.test", 15, "SAFE", "Low Risk", "URL", details_dict=None)

    resp = client.get(f"/api/history/{rec_id}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    rec = data["record"]
    assert rec["limited_data"] is True
    assert rec["score"] == 15
    assert rec["verdict"] == "SAFE"
    assert rec["can_rescan"] is True


def test_history_ownership_access_control(client):
    """Verify users cannot inspect or download PDF reports for records owned by other users."""
    user_a = "user_a@cyberscape.test"
    user_b = "user_b@cyberscape.test"

    rec_id = insert_scan_log(user_a, "https://private-user-a.test", 50, "SUSPICIOUS", "Elevated Risk", "URL")

    # Login as User B
    create_test_user_and_login(client, email=user_b)

    # 1. API inspection should be blocked with 403 Forbidden
    resp = client.get(f"/api/history/{rec_id}")
    assert resp.status_code == 403
    assert "Unauthorized" in resp.get_json().get("error", "")

    # 2. PDF download should also be blocked with 403 Forbidden
    pdf_resp = client.get(f"/history/{rec_id}/report.pdf")
    assert pdf_resp.status_code == 403


def test_history_record_pdf_generation(client):
    """Verify ReportLab PDF generation for a single historical scan record."""
    user = "dave@cyberscape.test"
    create_test_user_and_login(client, email=user)

    url_details = {
        "url": "https://threat-indicator.test/login",
        "domain": "threat-indicator.test",
        "score": 85,
        "status": "MALICIOUS",
        "signals": [{"title": "Phishing Keyword Match", "severity": "high", "explanation": "Suspicious login path"}]
    }
    rec_id = insert_scan_log(user, "https://threat-indicator.test/login", 85, "MALICIOUS", "High Risk", "URL", url_details)

    resp = client.get(f"/history/{rec_id}/report.pdf")
    assert resp.status_code == 200
    assert resp.content_type == "application/pdf"
    assert resp.data.startswith(b"%PDF")
    assert f"CyberScape_Report_URL_{rec_id}_" in resp.headers.get("Content-Disposition", "")


def test_history_export_all_pdf(client):
    """Verify consolidated multi-record audit trail PDF generation."""
    user = "ellen@cyberscape.test"
    create_test_user_and_login(client, email=user)

    insert_scan_log(user, "https://alpha.test", 10, "SAFE", "Low Risk", "URL")
    insert_scan_log(user, "https://beta.test", 80, "MALICIOUS", "High Risk", "URL")
    insert_scan_log(user, "alert@gamma.test", 45, "SUSPICIOUS", "Elevated Risk", "EMAIL")

    resp = client.get("/history/export-all.pdf")
    assert resp.status_code == 200
    assert resp.content_type == "application/pdf"
    assert resp.data.startswith(b"%PDF")
    assert "CyberScape_All_History_" in resp.headers.get("Content-Disposition", "")


def test_dashboard_stats_and_logs(client):
    """Verify /api/dashboard/stats and /api/dashboard/logs calculate accurate totals including emails."""
    user = "frank@cyberscape.test"
    create_test_user_and_login(client, email=user)

    insert_scan_log(user, "https://site1.test", 0, "SAFE", "Low Risk", "URL")
    insert_scan_log(user, "https://site2.test", 0, "SAFE", "Low Risk", "URL")
    insert_scan_log(user, "https://site3.test", 90, "MALICIOUS", "High Risk", "QR")
    insert_scan_log(user, "billing@scam.test — Invoice Due", 95, "MALICIOUS", "High Risk", "EMAIL")

    # 1. Stats verification
    stats_resp = client.get("/api/dashboard/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.get_json()
    assert stats["success"] is True
    assert stats["url"] == 2
    assert stats["qr"] == 1
    assert stats["email"] == 1
    assert stats["total"] == 4  # Total must equal url + qr + email
    assert stats["safe"] == 2
    assert stats["blocked"] == 2

    # 2. Filter by EMAIL in logs
    logs_email = client.get("/api/dashboard/logs?source=EMAIL")
    assert logs_email.status_code == 200
    logs_data = logs_email.get_json()
    assert logs_data["success"] is True
    assert len(logs_data["logs"]) == 1
    assert logs_data["logs"][0]["source"] == "EMAIL"
    assert "billing@scam.test" in logs_data["logs"][0]["url"]

    # 3. Search query across email
    logs_search = client.get("/api/dashboard/logs?q=Invoice")
    assert logs_search.status_code == 200
    search_data = logs_search.get_json()
    assert len(search_data["logs"]) == 1
    assert "Invoice Due" in search_data["logs"][0]["url"]

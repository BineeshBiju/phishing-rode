"""
Integration test suite for Real-Time Activity Logging Only & Clean State
Validates:
1. Brand-new user accounts start with 0 Total Ingress Logs and empty state placeholder.
2. Logging only occurs upon active URL, QR, or Email scans.
3. Every database entry contains real destination, score, timestamp, and scan type.
4. Summary metrics dynamically calculate exclusively from the active user's scan history.
5. PDF forensic report generation works seamlessly for every logged scan entry.
6. User scan history isolation between accounts.
"""

import pytest
import uuid
import io
from app import app, get_db


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_brand_new_user_starts_with_clean_empty_history(client):
    """Verify that a newly registered user account has 0 logs across dashboard and stats."""
    uid = uuid.uuid4().hex[:8]
    new_email = f"clean_{uid}@cyberscape.test"
    phone = f"+1555{int(uuid.uuid4()) % 10000000:07d}"
    res = client.post("/register", data={
        "name": f"Clean Analyst {uid}",
        "email": new_email,
        "phone": phone,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)
    assert res.status_code == 200

    # 1. Check /api/dashboard/stats
    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    stats = stats_res.get_json()
    assert stats["success"] is True
    assert stats["total"] == 0
    assert stats["safe"] == 0
    assert stats["suspicious"] == 0
    assert stats["blocked"] == 0
    assert stats["url"] == 0
    assert stats["qr"] == 0
    assert stats["email"] == 0

    # 2. Check /api/dashboard/logs
    logs_res = client.get("/api/dashboard/logs")
    assert logs_res.status_code == 200
    logs_data = logs_res.get_json()
    assert logs_data["success"] is True
    assert logs_data["total"] == 0
    assert len(logs_data["logs"]) == 0

    # 3. Check /dashboard HTML rendering
    dash_res = client.get("/dashboard")
    assert dash_res.status_code == 200
    html = dash_res.data.decode("utf-8")
    assert '<b id="statTotal">0</b>' in html
    assert '<span id="countAllLogs">0</span>' in html
    assert '<span id="countUrlProbes">0</span>' in html
    assert '<span id="countQrDecodes">0</span>' in html
    assert "No forensic records logged yet" in html


def test_real_time_url_scan_populates_dashboard(client):
    """Verify scanning a URL adds a genuine row and updates metrics dynamically."""
    uid = uuid.uuid4().hex[:8]
    user_email = f"url_tester_{uid}@cyberscape.test"
    phone = f"+1555{int(uuid.uuid4()) % 10000000:07d}"
    client.post("/register", data={
        "name": f"URL Tester {uid}",
        "email": user_email,
        "phone": phone,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)

    target_url = "https://en.wikipedia.org/wiki/Computer_security"
    scan_res = client.post("/check-url", json={"url": target_url})
    assert scan_res.status_code == 200
    scan_data = scan_res.get_json()
    assert scan_data["status"] in ["SAFE", "MALICIOUS", "SUSPICIOUS"]

    # Verify metrics updated to 1
    stats_res = client.get("/api/dashboard/stats")
    stats = stats_res.get_json()
    assert stats["total"] == 1
    assert stats["url"] == 1
    assert stats["qr"] == 0
    assert stats["email"] == 0

    # Verify row in /api/dashboard/logs
    logs_res = client.get("/api/dashboard/logs")
    logs = logs_res.get_json()["logs"]
    assert len(logs) == 1
    assert logs[0]["url"] == target_url
    assert logs[0]["source"] == "URL"
    assert logs[0]["status"] == scan_data["status"]

    # Verify /dashboard HTML contains the scanned target
    dash_html = client.get("/dashboard").data.decode("utf-8")
    assert '<b id="statTotal">1</b>' in dash_html
    assert target_url in dash_html
    assert "Wikipedia" in dash_html or "wikipedia.org" in dash_html


def test_real_time_qr_scan_populates_dashboard(client):
    """Verify scanning a QR destination adds an authentic QR row and updates QR counter."""
    uid = uuid.uuid4().hex[:8]
    user_email = f"qr_tester_{uid}@cyberscape.test"
    phone = f"+1555{int(uuid.uuid4()) % 10000000:07d}"
    client.post("/register", data={
        "name": f"QR Tester {uid}",
        "email": user_email,
        "phone": phone,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)

    qr_url = f"https://example.com/qr-active-destination-{uid}"
    qr_res = client.post("/qr-result", json={"url": qr_url})
    assert qr_res.status_code == 200

    # Verify metrics
    stats = client.get("/api/dashboard/stats").get_json()
    assert stats["total"] == 1
    assert stats["qr"] == 1
    assert stats["url"] == 0

    # Filter logs by source=QR
    qr_logs = client.get("/api/dashboard/logs?source=QR").get_json()["logs"]
    assert len(qr_logs) == 1
    assert qr_logs[0]["url"] == qr_url
    assert qr_logs[0]["source"] == "QR"


def test_real_time_email_scan_populates_dashboard(client):
    """Verify analyzing an email logs an authentic EMAIL row and updates metrics."""
    uid = uuid.uuid4().hex[:8]
    user_email = f"email_tester_{uid}@cyberscape.test"
    phone = f"+1555{int(uuid.uuid4()) % 10000000:07d}"
    client.post("/register", data={
        "name": f"Email Tester {uid}",
        "email": user_email,
        "phone": phone,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)

    test_header = "From: security-alert@bank-update-notice.xyz\nSubject: Account suspended\nDate: Tue, 10 Nov 2026 12:00:00 +0000"
    test_body = "Your account has been locked. Verify immediately at http://bank-update-notice.xyz/verify or lose access."

    email_res = client.post("/analyze-email", json={
        "header_text": test_header,
        "content_text": test_body
    })
    assert email_res.status_code == 200

    # Verify metrics
    stats = client.get("/api/dashboard/stats").get_json()
    assert stats["total"] == 1
    assert stats["email"] == 1

    # Filter logs by source=EMAIL
    email_logs = client.get("/api/dashboard/logs?source=EMAIL").get_json()["logs"]
    assert len(email_logs) == 1
    assert email_logs[0]["source"] == "EMAIL"


def test_pdf_report_generation_for_logged_entry(client):
    """Verify that every real logged scan can generate and download a valid forensic PDF report."""
    uid = uuid.uuid4().hex[:8]
    user_email = f"pdf_tester_{uid}@cyberscape.test"
    phone = f"+1555{int(uuid.uuid4()) % 10000000:07d}"
    client.post("/register", data={
        "name": f"PDF Tester {uid}",
        "email": user_email,
        "phone": phone,
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)

    target_url = f"https://example.com/pdf-audit-target-{uid}"
    client.post("/check-url", json={"url": target_url})

    pdf_res = client.get(f"/generate-report?url={target_url}")
    assert pdf_res.status_code == 200
    assert pdf_res.mimetype == "application/pdf"
    assert len(pdf_res.data) > 500
    assert pdf_res.data[:4] == b"%PDF"


def test_user_history_isolation(client):
    """Verify that User B cannot see User A's scans and starts with a pristine 0 count."""
    uid_a = uuid.uuid4().hex[:8]
    uid_b = uuid.uuid4().hex[:8]

    # User A performs 2 scans
    client.post("/register", data={
        "name": f"User Alpha {uid_a}",
        "email": f"alpha_{uid_a}@cyberscape.test",
        "phone": f"+1555{int(uuid.uuid4()) % 10000000:07d}",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)
    client.post("/check-url", json={"url": f"https://alpha-{uid_a}-one.org"})
    client.post("/check-url", json={"url": f"https://alpha-{uid_a}-two.org"})
    assert client.get("/api/dashboard/stats").get_json()["total"] == 2

    # Logout and register User B
    client.get("/logout")
    client.post("/register", data={
        "name": f"User Beta {uid_b}",
        "email": f"beta_{uid_b}@cyberscape.test",
        "phone": f"+1555{int(uuid.uuid4()) % 10000000:07d}",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }, follow_redirects=True)

    # User B must have 0 logs
    beta_stats = client.get("/api/dashboard/stats").get_json()
    assert beta_stats["total"] == 0
    assert beta_stats["url"] == 0

    beta_logs = client.get("/api/dashboard/logs").get_json()["logs"]
    assert len(beta_logs) == 0

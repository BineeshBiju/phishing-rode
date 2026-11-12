"""
Unit and Integration Tests for Admin History & Forensic Logs Component
Tests:
- Admin dashboard route (/admin and /dashboard)
- Navigation bar CYBERSPACE brand and active Dashboard link
- Search filter controls and pill tabs (All Logs, URL Probes, QR Decodes)
- Table columns structure and forensic action buttons
"""

import pytest
from app import app, get_db


@pytest.fixture()
def authenticated_client():
    app.config.update(TESTING=True)
    with get_db() as conn:
        conn.execute("DELETE FROM scan_logs WHERE user_email = 'admin@cyberscape.test'")
    with app.test_client() as client:
        # Log in as admin
        client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=True
        )
        yield client


def test_admin_dashboard_navigation_and_brand(authenticated_client):
    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "CYBERSPACE" in html
    assert ">Overview<" not in html
    assert "URL Scanner" in html
    assert "QR Scanner" in html
    assert "AI Email Analyzer" in html
    assert "Dashboard" in html
    assert "Logout" in html
    assert 'class="nav-logout"' in html
    assert "Ingress Scan History & Forensic Logs" in html
    assert "Filter by URL, host, or status..." in html


def test_fresh_user_starts_with_empty_logs(authenticated_client):
    """Test that a clean user account starts with 0 logs and empty state notice."""
    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Table Headers (6 Columns)
    assert "TARGET DESTINATION" in html
    assert "INGRESS" in html
    assert "PHISHING RISK SCORE" in html
    assert "THREAT STATUS" in html
    assert "TIMESTAMP" in html
    assert "FORENSIC ACTIONS" in html

    # Clean initial state (0 logs)
    assert 'id="countAllLogs">0</span>' in html or 'id="countAllLogs"> 0 </span>' in html or 'id="statTotal">0</b>' in html
    assert "No forensic records logged yet" in html


def test_admin_table_columns_and_real_scan_logging(authenticated_client):
    """Test that performing a real scan dynamically logs into the database and populates dashboard."""
    scan_url = "https://example.com/test-live-probe"
    scan_res = authenticated_client.post("/check-url", json={"url": scan_url})
    assert scan_res.status_code == 200

    response = authenticated_client.get("/admin")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Table Headers (6 Columns)
    assert "TARGET DESTINATION" in html
    assert "INGRESS" in html
    assert "PHISHING RISK SCORE" in html
    assert "THREAT STATUS" in html
    assert "TIMESTAMP" in html
    assert "FORENSIC ACTIONS" in html

    # Real scan record appears
    assert scan_url in html
    assert "HTTPS" in html
    assert "Host:" in html
    assert "example.com" in html
    assert "PDF Report" in html
    assert "Inspect" in html


def test_tab_filter_counts_and_spacing(authenticated_client):
    """Test that tab filters reflect real user scans dynamically."""
    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "All Logs (" in html
    assert "URL Probes (" in html
    assert "QR Decodes (" in html


def test_unauthenticated_dashboard_direct_access():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        response = client.get("/dashboard")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "CYBERSPACE" in html
        assert "Dashboard" in html
        assert "Logout" in html


def test_audit_overview_and_logs_integration(authenticated_client):
    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Threat Intelligence Map was removed as requested
    assert "Interactive Threat Intelligence Map" not in html
    assert "threatMap" not in html
    assert "leaflet.js" not in html

    # Audit Overview & Ingress Scan History are present
    assert "Audit overview" in html
    assert "auditOverviewSection" in html
    assert "Ingress Scan History & Forensic Logs" in html
    assert "Why this score?" in html


def test_threat_map_endpoint(authenticated_client):
    response = authenticated_client.get("/threat-map-data")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert "count" in data
    assert "data" in data


"""
Unit and Integration Tests for Admin History & Forensic Logs Component
Tests:
- Admin dashboard route (/admin and /dashboard)
- Navigation bar CYBERSPACE brand and active Dashboard link
- Search filter controls and pill tabs (All Logs, URL Probes, QR Decodes)
- Table columns structure and forensic action buttons
"""

import pytest
from app import app


@pytest.fixture()
def authenticated_client():
    app.config.update(TESTING=True)
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
    assert "Overview" in html
    assert "URL Scanner" in html
    assert "QR Scanner" in html
    assert "AI Email Analyzer" in html
    assert "Dashboard" in html
    assert "Logout" in html
    assert 'class="nav-logout"' in html
    assert "Ingress Scan History & Forensic Logs" in html
    assert "Filter by URL, host, or status..." in html


def test_admin_table_columns_and_sample_row(authenticated_client):
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

    # Sample Target row
    assert "https://example.com/test-pdf" in html
    assert "HTTPS" in html
    assert "Host:" in html
    assert "example.com" in html
    assert "RESERVED-Internet Assigned Numbers Authority" in html
    assert "2026-10-16 23:37:58" in html
    assert "LOW RISK" in html
    assert "PDF Report" in html
    assert "Inspect" in html


def test_tab_filter_counts_and_spacing(authenticated_client):
    response = authenticated_client.get("/dashboard")
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "All Logs ( <span id=\"countAllLogs\">50</span> )" in html
    assert "URL Probes ( <span id=\"countUrlProbes\">31</span> )" in html
    assert "QR Decodes ( <span id=\"countQrDecodes\">19</span> )" in html


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
    assert data["count"] > 0
    assert len(data["data"]) > 0
    sample = data["data"][0]
    assert "lat" in sample
    assert "lon" in sample
    assert "city" in sample
    assert "country" in sample
    assert "url" in sample


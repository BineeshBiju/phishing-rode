"""
Tests for Landing Page Feature Visibility and Dashboard Authentication Access Control
Verifies:
1. Guest / Unauthenticated Visitor:
   - Landing page (/) shows all features: Overview, URL Scanner, QR Scanner, AI Email Analyzer
   - Dashboard link is NOT visible in navigation
   - Logout link is NOT visible; Login & Sign In buttons are visible
   - Feature pages (/scanner, /qr-scanner, /email-analyzer) are viewable with Preview Mode banner
   - Direct access to /dashboard or /admin redirects to /login (302)
   - Scan APIs (/api/check-url, /api/qr-result, etc.) reject unauthenticated requests with 401
2. Authenticated User:
   - Dashboard link IS visible in navigation
   - Logout link IS visible in navigation
   - Direct access to /dashboard displays full Threat Map & Logs (200)
   - All scan APIs execute properly and return threat analysis (200)
"""

import pytest
from app import app


@pytest.fixture()
def guest_client():
    """Client simulating an unauthenticated visitor (TESTING=False during route checks)"""
    app.config.update(TESTING=False)
    with app.test_client() as client:
        yield client
    app.config.update(TESTING=True)


@pytest.fixture()
def logged_in_client():
    """Client simulating an authenticated user who logged in via /login"""
    app.config.update(TESTING=False)
    with app.test_client() as client:
        client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=True
        )
        yield client
    app.config.update(TESTING=True)


def test_guest_landing_page_features_visible_dashboard_not_visible(guest_client):
    response = guest_client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Brand
    assert "CYBERSPACE" in html

    # All features are visible
    assert "Overview" in html
    assert "URL Scanner" in html
    assert "QR Scanner" in html
    assert "AI Email Analyzer" in html

    # Showcase cards are visible
    assert "URL Threat Scanner" in html
    assert "Live QR Code Scanner" in html
    assert "AI Email & Header Tracker" in html
    assert "Quick Check" in html

    # Dashboard and Logout navigation items MUST NOT be visible
    assert '>Dashboard<' not in html
    assert 'href="/dashboard"' not in html
    assert 'href="/admin"' not in html
    assert '>Logout<' not in html
    assert 'href="/logout"' not in html
    assert 'class="nav-logout"' not in html

    # Login and Sign In buttons ARE visible in navigation
    assert "Login" in html
    assert "Sign In" in html


def test_guest_feature_pages_viewable_without_dashboard(guest_client):
    for path in ["/scanner", "/qr-scanner", "/email-analyzer"]:
        response = guest_client.get(path)
        assert response.status_code == 200
        html = response.data.decode("utf-8")

        # Features and Brand are visible
        assert "CYBERSPACE" in html
        assert "Overview" in html
        assert "URL Scanner" in html
        assert "QR Scanner" in html
        assert "AI Email Analyzer" in html

        # Dashboard and Logout nav links are NOT visible
        assert '>Dashboard<' not in html
        assert 'href="/dashboard"' not in html
        assert '>Logout<' not in html
        assert 'href="/logout"' not in html
        assert 'class="nav-logout"' not in html

        # Preview mode banner is shown
        assert "VIEW ONLY" in html


def test_guest_dashboard_direct_access_redirects_to_login(guest_client):
    # Direct access to /dashboard redirects to /login
    response = guest_client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    # Direct access to /admin redirects to /login
    response_admin = guest_client.get("/admin")
    assert response_admin.status_code == 302
    assert "/login" in response_admin.headers["Location"]


def test_guest_scan_api_rejects_with_401(guest_client):
    res_url = guest_client.post("/api/check-url", json={"url": "https://example.com"})
    assert res_url.status_code == 401
    assert "Authentication required" in res_url.get_json()["error"]

    res_qr = guest_client.post("/api/qr-result", json={"url": "https://example.com"})
    assert res_qr.status_code == 401
    assert "Authentication required" in res_qr.get_json()["error"]

    res_email = guest_client.post("/api/analyze-email", json={"header_text": "From: a@b.com", "content_text": "hi"})
    assert res_email.status_code == 401
    assert "Authentication required" in res_email.get_json()["error"]


def test_authenticated_user_dashboard_and_features_working(logged_in_client):
    # Landing page now has Dashboard and Logout visible
    home_res = logged_in_client.get("/")
    assert home_res.status_code == 200
    home_html = home_res.data.decode("utf-8")
    assert "Dashboard" in home_html
    assert "Logout" in home_html

    # Dashboard is accessible
    dash_res = logged_in_client.get("/dashboard")
    assert dash_res.status_code == 200
    dash_html = dash_res.data.decode("utf-8")
    assert "Interactive Threat Intelligence Map" in dash_html
    assert "Ingress Scan History & Forensic Logs" in dash_html

    # All scan features work properly
    scan_res = logged_in_client.post("/api/check-url", json={"url": "https://example.com/legit"})
    assert scan_res.status_code == 200
    scan_data = scan_res.get_json()
    assert scan_data["status"] in {"SAFE", "MALICIOUS", "UNKNOWN"}
    assert "score" in scan_data

    qr_res = logged_in_client.post("/api/qr-result", json={"url": "https://example.com/qr-dest"})
    assert qr_res.status_code == 200
    qr_data = qr_res.get_json()
    assert qr_data["source"] == "QR"

    email_res = logged_in_client.post(
        "/api/analyze-email",
        json={"header_text": "From: test@test.com", "content_text": "Hello test"}
    )
    assert email_res.status_code == 200
    assert "verdict" in email_res.get_json()

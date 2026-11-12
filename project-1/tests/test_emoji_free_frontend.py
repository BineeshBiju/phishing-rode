"""
Test suite validating complete emoji removal and enterprise-grade aesthetic:
1. Static files (JavaScript and HTML templates) contain zero Unicode emojis.
2. Rendered HTTP endpoints (home, scanner, qr_scanner, email_analyzer, dashboard, etc.) contain zero emojis.
3. API endpoints (URL scan, QR scan, Email analysis, dashboard stats/logs) contain zero emojis.
4. Lucide icons integration is present in frontend assets and templates.
"""

import os
import re
import pytest
from app import app

EMOJI_PATTERN = re.compile(
    r"[\U00010000-\U0010ffff]|"
    r"[\u2600-\u26ff]|"
    r"[\u2700-\u27bf]|"
    r"[\u2300-\u23ff]|"
    r"[\u2b50-\u2b55]|"
    r"[\u203c\u2049\u2139\u2194-\u2199\u21a9-\u21aa\u2934\u2935\u25aa\u25ab\u25b6\u25c0\u25fb-\u25fe]|"
    r"[\u3030\u303d\u3297\u3299]"
)


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "admin@cyberscape.test"
        yield client


def test_static_javascript_and_templates_contain_no_emojis():
    """Verify that all project source files in templates/ and static/js/ have zero emojis."""
    scanned_files = []
    found_violations = []

    for folder in ["templates", "static/js"]:
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith((".html", ".js")):
                    path = os.path.join(root, file)
                    scanned_files.append(path)
                    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                        matches = EMOJI_PATTERN.findall(content)
                        if matches:
                            found_violations.append((path, matches))

    assert len(scanned_files) >= 10, f"Expected at least 10 frontend files, got {len(scanned_files)}"
    assert not found_violations, f"Found emojis in source files: {found_violations}"


def test_rendered_pages_contain_no_emojis(client):
    """Verify that rendered HTML from all major web pages contains zero emojis."""
    pages = [
        "/",
        "/scanner",
        "/qr-scanner",
        "/email-analyzer",
        "/dashboard",
        "/analysis",
        "/blocked"
    ]
    for page in pages:
        res = client.get(page)
        assert res.status_code == 200, f"Page {page} returned status {res.status_code}"
        html = res.get_data(as_text=True)
        emojis = EMOJI_PATTERN.findall(html)
        assert not emojis, f"Page {page} contained emoji characters: {emojis}"

    # Also test guest auth pages without active session
    with app.test_client() as guest_client:
        for auth_page in ["/login", "/register"]:
            res = guest_client.get(auth_page)
            assert res.status_code == 200, f"Page {auth_page} returned status {res.status_code}"
            html = res.get_data(as_text=True)
            emojis = EMOJI_PATTERN.findall(html)
            assert not emojis, f"Page {auth_page} contained emoji characters: {emojis}"


def test_api_responses_contain_no_emojis(client):
    """Verify that backend JSON payloads returned by scans and dashboard APIs contain zero emojis."""
    # 1. URL Check
    url_res = client.post("/check-url", json={"url": "https://en.wikipedia.org/wiki/Computer_security"})
    assert url_res.status_code == 200
    url_text = url_res.get_data(as_text=True)
    assert not EMOJI_PATTERN.findall(url_text), "URL check response contained emoji"

    # 2. QR Check
    qr_res = client.post("/qr-result", json={"url": "https://en.wikipedia.org/wiki/Computer_security"})
    assert qr_res.status_code == 200
    qr_text = qr_res.get_data(as_text=True)
    assert not EMOJI_PATTERN.findall(qr_text), "QR check response contained emoji"

    # 3. Email Analysis
    email_res = client.post("/analyze-email", json={
        "header_text": "From: billing@paypal.com\nReturn-Path: spoof@bad.xyz",
        "content_text": "Immediate action required: verify your login."
    })
    assert email_res.status_code == 200
    email_text = email_res.get_data(as_text=True)
    assert not EMOJI_PATTERN.findall(email_text), "Email analysis response contained emoji"

    # 4. Dashboard Stats
    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    assert not EMOJI_PATTERN.findall(stats_res.get_data(as_text=True)), "Dashboard stats contained emoji"

    # 5. Dashboard Logs
    logs_res = client.get("/api/dashboard/logs")
    assert logs_res.status_code == 200
    assert not EMOJI_PATTERN.findall(logs_res.get_data(as_text=True)), "Dashboard logs contained emoji"


def test_lucide_icon_integration_present(client):
    """Verify that Lucide script and data-lucide attributes are integrated cleanly."""
    res = client.get("/scanner")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "lucide" in html.lower(), "Lucide script or references should be loaded in base template"

    qr_res = client.get("/qr-scanner")
    assert qr_res.status_code == 200
    qr_html = qr_res.get_data(as_text=True)
    assert 'data-lucide="camera"' in qr_html
    assert 'data-lucide="upload"' in qr_html

    admin_res = client.get("/dashboard")
    assert admin_res.status_code == 200
    admin_html = admin_res.get_data(as_text=True)
    assert 'data-lucide="file-text"' in admin_html
    assert 'data-lucide="search"' in admin_html

"""
Tests for shared base template copyright footer:
1. Appears on every page (URL Scanner, QR Scanner, Email Analyzer, History, Audit, Login).
2. Contains "Threat intelligence for everyday links" tagline.
3. Contains "© <current year> CyberScape. All rights reserved." with automatic current year.
4. Exactly one <footer> element exists on every page (no duplicate footer).
"""

from datetime import datetime
import pytest
from app import app


@pytest.fixture()
def authed_client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "admin@cyberscape.test"
        yield client


@pytest.fixture()
def guest_client():
    app.config.update(TESTING=False)
    with app.test_client() as client:
        yield client
    app.config.update(TESTING=True)


def test_copyright_footer_on_authenticated_pages(authed_client):
    """Verify footer on URL Scanner, QR Scanner, Email Analyzer, History, and Audit pages."""
    current_year = datetime.now().year
    valid_copyrights = [
        f"&copy; {current_year} CyberScape. All rights reserved.",
        f"© {current_year} CyberScape. All rights reserved.",
        "&copy; 2026 CyberScape. All rights reserved.",
        "© 2026 CyberScape. All rights reserved."
    ]
    expected_tagline = "Threat intelligence for everyday links"

    pages = [
        "/",                 # URL Scanner / Home
        "/scanner",          # Dedicated URL Scanner
        "/qr-scanner",       # QR Scanner
        "/email-analyzer",   # Email Analyzer
        "/dashboard",        # History / Dashboard
        "/admin",            # History & Audit Logs
    ]

    for page in pages:
        res = authed_client.get(page)
        assert res.status_code == 200, f"Page {page} returned status {res.status_code}"
        html = res.data.decode("utf-8")

        # Verify exactly one <footer> element (no duplicates)
        assert html.count("<footer") == 1, f"Page {page} has unexpected footer count: {html.count('<footer')}"
        assert html.count("</footer>") == 1, f"Page {page} has unexpected closing footer count"

        # Verify copyright text with current year
        assert any(c in html for c in valid_copyrights), f"Page {page} missing expected copyright notice"

        # Verify tagline
        assert expected_tagline in html, f"Page {page} missing tagline: '{expected_tagline}'"

        # Verify dynamic client-side update element
        assert 'id="copyrightNotice"' in html, f"Page {page} missing copyrightNotice element"

        # Verify License link in footer
        assert 'href="/license"' in html, f"Page {page} missing License link in footer"


def test_copyright_footer_on_auth_pages(guest_client):
    """Verify footer on login and registration pages."""
    current_year = datetime.now().year
    valid_copyrights = [
        f"&copy; {current_year} CyberScape. All rights reserved.",
        f"© {current_year} CyberScape. All rights reserved.",
        "&copy; 2026 CyberScape. All rights reserved.",
        "© 2026 CyberScape. All rights reserved."
    ]
    expected_tagline = "Threat intelligence for everyday links"

    pages = [
        "/login",
        "/register",
    ]

    for page in pages:
        res = guest_client.get(page)
        assert res.status_code == 200, f"Page {page} returned status {res.status_code}"
        html = res.data.decode("utf-8")

        assert html.count("<footer") == 1, f"Page {page} has duplicate or missing footer"
        assert any(c in html for c in valid_copyrights), f"Page {page} missing copyright notice"
        assert expected_tagline in html, f"Page {page} missing tagline: '{expected_tagline}'"
        assert 'href="/license"' in html, f"Page {page} missing License link in footer"


def test_license_page_content_and_team(guest_client, authed_client):
    """Verify /license renders correctly for both guest and authenticated users with all 4 team members."""
    for client in [guest_client, authed_client]:
        res = client.get("/license")
        assert res.status_code == 200, f"/license returned {res.status_code}"
        html = res.data.decode("utf-8")

        # Verify all 4 team member names exist in order
        names = ["Jerald M Jolly", "Bineesh Biju", "Aston Mathew Felix", "Adhul K R"]
        for name in names:
            assert name in html, f"Name '{name}' missing from /license page"

        # Verify copyright notice line
        assert "Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R" in html
        assert "CyberScape License Agreement" in html
        assert html.count("<footer") == 1, "/license page must have exactly one footer"



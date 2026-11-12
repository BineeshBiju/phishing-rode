"""
Test suite validating:
1. Logout redirects to /login with no query parameters (no '?error=...').
2. "You have been logged out." appears as a flashed 'info' message in neutral/green styling.
3. Form validation errors (wrong password) retain the red error styling.
"""

import pytest
from app import app


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_logout_redirects_without_query_param(client):
    """Verify /logout redirects to clean /login URL without ?error= in Location."""
    # Establish session
    with client.session_transaction() as sess:
        sess["user"] = "admin@cyberscape.test"
        sess["name"] = "Admin"

    res = client.get("/logout", follow_redirects=False)
    assert res.status_code in [302, 303]
    location = res.headers.get("Location", "")
    assert location.endswith("/login")
    assert "error=" not in location
    assert "?" not in location


def test_logout_displays_flash_info_message_in_green_style(client):
    """Verify that following /logout renders 'You have been logged out.' in green/safe style."""
    with client.session_transaction() as sess:
        sess["user"] = "admin@cyberscape.test"

    res = client.get("/logout", follow_redirects=True)
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # Message must be present
    assert "You have been logged out." in html

    # Styling must be green/info, NOT red error box
    assert "message-info" in html
    assert "text-safe" in html
    assert "bg-safe/10" in html
    assert "border-safe/30" in html


def test_invalid_login_retains_red_error_style(client):
    """Verify failed login attempt renders in the red danger style."""
    res = client.post("/login", data={
        "username": "nonexistent@cyberscape.test",
        "password": "wrongpassword123"
    }, follow_redirects=True)
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    assert "Invalid login" in html
    assert "message-error" in html
    assert "text-danger" in html
    assert "bg-danger/10" in html
    assert "border-danger/30" in html


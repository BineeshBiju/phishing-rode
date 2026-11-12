"""
Test suite validating that Google OAuth 2.0 has been completely removed:
1. "Sign in with Google" button and "OR" divider are completely removed from /login.
2. "Sign up with Google" button and "OR" divider are completely removed from /register.
3. Standard username/password login, remember me, and registration forms remain fully intact.
4. Legacy Google OAuth routes (/auth/google, /auth/google/callback, etc.) return 404.
5. Standard login, signup, and logout operations function seamlessly.
"""

import uuid
import pytest
from app import app, get_db


@pytest.fixture()
def guest_client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_login_page_has_no_google_oauth_elements(guest_client):
    """Ensure /login has no Google Sign-In button, OR divider, or Google SDK scripts."""
    res = guest_client.get("/login")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    # 1. Google OAuth UI elements must NOT be present
    assert "btn-google-auth" not in html
    assert "Sign in with Google" not in html
    assert "google-icon" not in html
    assert "auth-divider" not in html
    assert "accounts.google.com/gsi/client" not in html
    assert "g_id_onload" not in html

    # 2. Standard form fields MUST be present and intact
    assert 'name="username"' in html
    assert 'name="password"' in html
    assert 'name="remember"' in html
    assert "Remember me" in html
    assert "Sign In" in html
    assert "Back to home" in html
    assert "New here?" in html
    assert "Create an account" in html


def test_register_page_has_no_google_oauth_elements(guest_client):
    """Ensure /register has no Google Sign-Up button or OR divider."""
    res = guest_client.get("/register")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    assert "btn-google-auth" not in html
    assert "Sign up with Google" not in html
    assert "google-icon" not in html
    assert "auth-divider" not in html

    # Standard form fields MUST be present
    assert 'name="name"' in html
    assert 'name="email"' in html
    assert 'name="phone"' in html
    assert 'name="password"' in html
    assert 'name="confirm_password"' in html
    assert "Create Account" in html
    assert "Already have an account? Sign In" in html


def test_google_oauth_endpoints_return_404(guest_client):
    """Ensure all former Google OAuth endpoints return 404 Not Found."""
    assert guest_client.get("/auth/google").status_code == 404
    assert guest_client.get("/auth/google/callback").status_code == 404
    assert guest_client.post("/auth/google/token", json={}).status_code == 404
    assert guest_client.post("/auth/google/dev-login", json={}).status_code == 404


def test_standard_signup_login_logout_flow(guest_client):
    """Verify standard registration, login, and logout work end-to-end without Google OAuth."""
    unique_id = uuid.uuid4().hex[:6]
    test_email = f"user_{unique_id}@cyberscape.test"
    test_pass = "SecurePass123!"

    # 1. Registration
    reg_res = guest_client.post("/register", data={
        "name": f"Test User {unique_id}",
        "email": test_email,
        "phone": f"+1555{unique_id[:6]}",
        "password": test_pass,
        "confirm_password": test_pass
    }, follow_redirects=False)
    assert reg_res.status_code in [302, 303]
    assert "/admin" in reg_res.headers["Location"]

    # 2. Logout
    logout_res = guest_client.get("/logout", follow_redirects=False)
    assert logout_res.status_code in [302, 303]
    assert "/login" in logout_res.headers["Location"]

    # 3. Standard Login
    login_res = guest_client.post("/login", data={
        "username": test_email,
        "password": test_pass,
        "remember": "on"
    }, follow_redirects=False)
    assert login_res.status_code in [302, 303]
    assert "/admin" in login_res.headers["Location"]

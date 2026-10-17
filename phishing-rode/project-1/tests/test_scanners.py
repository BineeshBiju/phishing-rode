import pytest

from app import app


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_url_scanner_checks_a_real_https_url(client):
    response = client.post(
        "/api/check-url",
        json={"url": "https://example.com/products"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "URL"
    assert data["status"] in {"SAFE", "MALICIOUS", "UNKNOWN"}
    assert data["reasons"]
    assert any("URLhaus" in reason for reason in data["reasons"])


def test_url_scanner_rejects_non_web_input(client):
    response = client.post(
        "/api/check-url",
        json={"url": "ftp://example.com/file.zip"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "INVALID"
    assert "HTTP" in data["reasons"][0]


def test_qr_scanner_uses_live_url_checks(client):
    response = client.post(
        "/api/qr-result",
        json={"url": "https://example.com/qr-destination"},
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["source"] == "QR"
    assert data["status"] in {"SAFE", "MALICIOUS", "UNKNOWN"}
    assert data["reasons"]


def test_qr_scanner_page_layout_and_navigation(client):
    response = client.get("/qr-scanner")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 1. Top Navigation Bar
    assert "CYBERSPACE" in html
    assert "Overview" in html
    assert "URL Scanner" in html
    assert "QR Scanner" in html
    assert "AI Email Analyzer" in html
    assert "Dashboard" in html
    assert "Logout" in html
    assert 'class="nav-logout"' in html

    # 2. QR Scanner Module Page Layout
    assert "QR CHECK / 02" in html
    assert "Check a QR code" in html
    assert "Scan a QR code using your live webcam or upload an image file." in html


def test_qr_scanner_dual_mode_components(client):
    response = client.get("/qr-scanner")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # 3. Left Card: Dual Mode Input
    assert "Live Camera Scan" in html
    assert "Upload Image" in html
    assert "Start Camera" in html
    assert "scanner-reticle-overlay" in html
    assert "Drop a QR image here" in html
    assert "PNG, JPG, or WEBP up to 10 MB" in html
    assert "Choose image" in html
    assert "No image selected." in html

    # 4. Right Card: Extracted Destination & Scan Action
    assert "STEP 2 OF 2" in html
    assert "Extracted destination" in html
    assert "Waiting for QR scan or upload..." in html
    assert "Check destination" in html


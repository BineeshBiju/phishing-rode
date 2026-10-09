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

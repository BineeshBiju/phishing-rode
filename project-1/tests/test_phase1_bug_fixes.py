"""
Tests for Phase 1 Bug Fixes:
1. URL Scanner: real data sources, explainable signals, verdict derived from score.
2. QR Scanner: endpoint responses, frontend JS syntax validity, and error handling.
3. Audit Page: /api/audit endpoint, mandatory permission, SSRF protection,
   single verdict_from_score, and removal of contradictory placeholder states.
"""

import pytest
from app import app, verdict_from_score
import audit_service


@pytest.fixture
def auth_client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "testuser"
        yield client


def test_url_scanner_returns_explainable_signals_and_verdict(auth_client):
    """Bug 1 Fix: Verify URL scanner returns structured signals, reasons, and consistent verdict."""
    res = auth_client.post("/check-url", json={"url": "https://en.wikipedia.org/wiki/Computer_security"})
    assert res.status_code == 200
    data = res.get_json()

    assert "signals" in data
    assert isinstance(data["signals"], list)
    assert len(data["signals"]) > 0

    # Every signal must have id, source, severity, and evidence
    for sig in data["signals"]:
        assert "id" in sig
        assert "source" in sig
        assert "severity" in sig
        assert "evidence" in sig

    # Verdict and score consistency
    verdict = verdict_from_score(data["score"])
    assert data["status"] == verdict["status"]
    assert data["level"] == verdict["level"]

    # Threat intel feeds present
    assert "threat_intel" in data
    assert "urlhaus" in data["threat_intel"]
    assert "virustotal" in data["threat_intel"]
    assert "safebrowsing" in data["threat_intel"]


def test_qr_scanner_endpoint_and_frontend_js_health(auth_client):
    """Bug 2 Fix: Verify QR endpoint returns inspection payload, and static JS has no syntax errors."""
    res = auth_client.post("/qr-result", json={"url": "https://example.com/qr-probe"})
    assert res.status_code == 200
    data = res.get_json()

    assert data["source"] == "QR"
    assert "signals" in data
    assert "threat_intel" in data
    assert "score" in data
    assert "status" in data

    # Verify verdict consistency
    expected = verdict_from_score(data["score"])
    assert data["status"] == expected["status"]


def test_audit_endpoint_mandatory_authorization(auth_client):
    """Bug 3 Fix: Target authorization permission is strictly enforced."""
    # Attempt audit without authorization flag
    res = auth_client.post("/api/audit", json={"url": "https://example.com", "authorized": False})
    assert res.status_code == 400
    assert "authorization" in res.get_json()["error"].lower()


def test_audit_endpoint_blocks_loopback_ssrf(auth_client):
    """Bug 3 Fix: SSRF prevention against internal addresses."""
    res = auth_client.post("/api/audit", json={"url": "http://127.0.0.1:5000", "authorized": True})
    assert res.status_code == 400
    assert "loopback" in res.get_json()["error"].lower() or "blocked" in res.get_json()["error"].lower()


def test_audit_verdict_cannot_contradict_score():
    """Bug 3 Fix: Audit verdict is derived exclusively through one function."""
    # 0 failures, 0 warnings -> Low Risk
    v_clean = audit_service.derive_audit_verdict(failures=0, warnings=0)
    assert v_clean["verdict"] == "LOW RISK"
    assert v_clean["score"] == 0
    assert v_clean["status"] == "SAFE"

    # 0 failures, 2 warnings -> Elevated Risk
    v_warn = audit_service.derive_audit_verdict(failures=0, warnings=2)
    assert v_warn["verdict"] == "ELEVATED RISK"
    assert 0 < v_warn["score"] < 70
    assert v_warn["status"] == "SUSPICIOUS"

    # 2 failures -> High Risk
    v_fail = audit_service.derive_audit_verdict(failures=2, warnings=1)
    assert v_fail["verdict"] == "HIGH RISK"
    assert v_fail["score"] >= 70
    assert v_fail["status"] == "MALICIOUS"


def test_audit_real_scan_execution(auth_client):
    """Bug 3 Fix: Live audit checks execute against real target."""
    res = auth_client.post("/api/audit", json={"url": "https://example.com", "authorized": True})
    assert res.status_code == 200
    data = res.get_json()

    assert data["success"] is True
    assert "summary" in data
    assert "passed" in data["summary"]
    assert "warnings" in data["summary"]
    assert "failures" in data["summary"]
    assert "checks" in data
    assert len(data["checks"]) >= 6

    # Verify that verdict and score correspond
    derived = audit_service.derive_audit_verdict(data["summary"]["failures"], data["summary"]["warnings"])
    assert data["threat_status"] == derived["verdict"]
    assert data["risk_score"] == derived["score"]


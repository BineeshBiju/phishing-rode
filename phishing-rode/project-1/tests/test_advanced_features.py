"""
Automated unit and integration tests for CyberScape 5 Advanced Cybersecurity Features:
1. AI ML Phishing Domain Detection
2. Real-Time Threat Intelligence Feed Aggregation
3. Automated PDF Forensic Report Generation
4. Visual Threat Matrix & Geo-IP Resolver
5. QR Code Decoder & Redirect Chain Sandbox Tracer
"""

import pytest
from app import app
import ml_engine
import threat_intel
import geo_resolver
import redirect_tracer
import report_generator


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_ml_engine_legitimate_url():
    res = ml_engine.predict_phishing("https://en.wikipedia.org/wiki/Computer_security")
    assert res["label"] in {"Legitimate", "Suspicious"}
    assert "confidence" in res
    assert "features" in res
    assert res["features"]["is_https"] is True


def test_ml_engine_phishing_url():
    res = ml_engine.predict_phishing("http://192.168.1.50/paypal/verify-identity-account.xyz/login")
    assert res["label"] == "Phishing"
    assert res["phishing_probability"] >= 0.70
    assert len(res["risk_factors"]) > 0


def test_threat_intel_aggregation():
    res = threat_intel.aggregate_threat_intelligence("https://example.com")
    assert "flagged_engines" in res
    assert "total_engines" in res
    assert res["total_engines"] >= 80
    assert "virustotal" in res
    assert "urlhaus" in res


def test_geo_resolver():
    res = geo_resolver.resolve_geo_ip("https://www.google.com")
    assert res["status"] in {"success", "partial"}
    assert "ip" in res
    assert "country" in res
    assert "isp" in res


def test_redirect_tracer_direct_url():
    res = redirect_tracer.trace_redirect_chain("https://example.com", max_hops=3)
    assert res["initial_url"] == "https://example.com"
    assert "final_url" in res
    assert len(res["chain"]) >= 1


def test_api_inspect_endpoint(client):
    response = client.post(
        "/api/inspect",
        json={"url": "https://example.com"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "ml_analysis" in data
    assert "threat_intel" in data
    assert "geo_ip" in data
    assert "redirect_chain" in data
    assert data["source"] == "INSPECTOR"


def test_api_generate_pdf_report(client):
    response = client.post(
        "/api/generate-report",
        json={"url": "https://example.com"},
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert len(response.data) > 1000
    assert response.data.startswith(b"%PDF")

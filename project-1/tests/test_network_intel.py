"""
Unit Tests for CyberScape Network Intelligence & Geolocation Service
Tests DNS resolution, SSRF blocking, CDN detection, multi-tier fallback resilience,
multi-country redirect signals, and safety invariance (geo data alone never pushes clean domain > low risk).
"""

from unittest.mock import patch, MagicMock
import pytest

from services.network_intel import (
    resolve_host,
    geolocate,
    is_private_ip,
    detect_cdn,
    build_network_report,
    evaluate_network_signals,
    clear_geo_cache
)
from backend.services.orchestrator import scan_url, clear_scan_cache


@pytest.fixture(autouse=True)
def clean_cache():
    """Ensure clean cache before and after every test."""
    clear_geo_cache()
    clear_scan_cache()
    yield
    clear_geo_cache()
    clear_scan_cache()


def test_ssrf_private_and_loopback_ips_blocked():
    """Requirement (c): private/loopback IP -> blocked_private_ip, no geo call."""
    test_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.100", "172.16.5.4", "169.254.169.254", "::1"]
    for ip in test_ips:
        assert is_private_ip(ip) is True
        # Mock requests.get to assert NO external network call is made
        with patch("requests.get") as mock_get:
            res = geolocate(ip)
            mock_get.assert_not_called()
            assert res["status"] == "blocked_private_ip"
            assert res["country_code"] == "XX"
            assert res["ip"] == ip


def test_host_with_multiple_ips():
    """Requirement (a): a host with 2 IPs -> two rows, both geolocated."""
    mock_host = "dual-ip-target.example"

    # Mock dnspython DNS resolver to return two distinct IP addresses
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        # First call is for 'A' records, second for 'AAAA'
        mock_rdata1 = MagicMock()
        mock_rdata1.to_text.return_value = "93.184.216.34"
        mock_rdata2 = MagicMock()
        mock_rdata2.to_text.return_value = "93.184.216.35"
        mock_rrset = MagicMock()
        mock_rrset.ttl = 300

        mock_answer_a = MagicMock()
        mock_answer_a.__iter__.return_value = [mock_rdata1, mock_rdata2]
        mock_answer_a.rrset = mock_rrset

        def side_effect(qname, rdtype):
            if rdtype == "A":
                return mock_answer_a
            raise Exception("No AAAA")

        mock_resolve.side_effect = side_effect

        with patch("services.network_intel.get_ptr_record", return_value="dual.edge.example"):
            res = resolve_host(mock_host)

        assert res["host"] == mock_host
        assert res["a_record_count"] == 2
        assert len(res["ips"]) == 2
        ip_addresses = [item["ip"] for item in res["ips"]]
        assert "93.184.216.34" in ip_addresses
        assert "93.184.216.35" in ip_addresses
        for item in res["ips"]:
            assert item["accuracy"] == "approximate"
            assert item["ptr"] == "dual.edge.example"


def test_cloudflare_cdn_detection_and_no_penalty():
    """Requirement (b): Cloudflare ASN -> is_cdn true and the CDN note signal, no penalty."""
    cf_ip = "104.16.132.229"

    # Mock ipwho.is returning Cloudflare connection
    mock_payload = {
        "success": True,
        "ip": cf_ip,
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.77,
        "longitude": -122.41,
        "connection": {
            "asn": 13335,
            "org": "Cloudflare, Inc.",
            "isp": "Cloudflare, Inc."
        },
        "timezone": {"id": "America/Los_Angeles"}
    }

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_payload
        mock_get.return_value = mock_resp

        geo_res = geolocate(cf_ip)

    assert geo_res["is_cdn"] is True
    assert geo_res["cdn_name"] == "Cloudflare"
    assert geo_res["asn"] == "AS13335"

    # Evaluate signals for Cloudflare CDN host
    net_report = {
        "hosts": [{
            "host": "example-cdn.com",
            "hop_index": 0,
            "role": "final",
            "ips": [geo_res],
            "ttl": 300,
            "a_record_count": 1
        }],
        "countries_in_path": ["US"],
        "summary": "Final destination is hosted by Cloudflare, Inc. (San Francisco, US) behind Cloudflare."
    }

    signals = evaluate_network_signals(net_report, context_flags={"is_lookalike": False})
    cdn_signals = [s for s in signals if "cdn" in s["id"]]
    assert len(cdn_signals) == 1
    assert cdn_signals[0]["severity"] == "info"
    assert cdn_signals[0]["score_impact"] == 0
    assert "real origin server location is hidden" in cdn_signals[0]["evidence"]


def test_provider_fallback_resilience():
    """Requirement (d): provider down -> falls back to the second provider, then to 'Geo-IP unavailable' without failing."""
    test_ip = "8.8.8.8"

    # Scenario 1: First provider (ipwho.is) fails (500), second provider (ipinfo.io) succeeds
    with patch("services.network_intel._geolocate_maxmind", return_value=None), \
         patch("services.network_intel._geolocate_ipwhois", return_value=None), \
         patch("services.network_intel._geolocate_ipinfo") as mock_ipinfo:

        mock_ipinfo.return_value = {
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "city": "Mountain View",
            "lat": 37.4,
            "lon": -122.08,
            "timezone": "America/Los_Angeles",
            "asn": "AS15169",
            "org": "Google LLC",
            "isp": "Google LLC",
            "is_hosting": False,
            "is_proxy_or_vpn": False,
            "geo_source": "ipinfo.io"
        }

        res = geolocate(test_ip)
        assert res["status"] == "ok"
        assert res["geo_source"] == "ipinfo.io"
        assert res["city"] == "Mountain View"

    clear_geo_cache()

    # Scenario 2: ALL online providers timeout / fail -> returns 'unavailable' gracefully without crash
    with patch("services.network_intel._geolocate_maxmind", return_value=None), \
         patch("services.network_intel._geolocate_ipwhois", return_value=None), \
         patch("services.network_intel._geolocate_ipinfo", return_value=None), \
         patch("services.network_intel._geolocate_ipapi", return_value=None), \
         patch("services.network_intel.geo_resolver", None):

        # Public IP (not reserved/private) that fails all providers
        res_unavailable = geolocate("142.250.190.46")
        assert res_unavailable["status"] == "unavailable"
        assert res_unavailable["geo_source"] == "unavailable"


def test_multi_country_redirect_chain_signal():
    """Requirement (e): 3-country redirect chain -> low signal only."""
    net_report = {
        "hosts": [
            {"host": "hop1.in", "hop_index": 0, "role": "original", "ips": [{"ip": "1.1.1.1", "country_code": "IN", "city": "Mumbai", "org": "Tata", "asn": "AS4755"}]},
            {"host": "hop2.de", "hop_index": 1, "role": "redirect", "ips": [{"ip": "2.2.2.2", "country_code": "DE", "city": "Frankfurt", "org": "Hetzner", "asn": "AS24940"}]},
            {"host": "hop3.us", "hop_index": 2, "role": "final", "ips": [{"ip": "3.3.3.3", "country_code": "US", "city": "San Jose", "org": "Equinix", "asn": "AS13335"}]}
        ],
        "countries_in_path": ["IN", "DE", "US"],
        "summary": "Multi-hop redirect chain across 3 countries."
    }

    signals = evaluate_network_signals(net_report, context_flags={"is_lookalike": False})
    multi_country_sig = [s for s in signals if s["id"] == "multi_country_redirect_chain"]
    assert len(multi_country_sig) == 1
    assert multi_country_sig[0]["severity"] == "low"
    assert multi_country_sig[0]["score_impact"] == 6
    assert "3 distinct jurisdictions" in multi_country_sig[0]["evidence"]


def test_geo_data_alone_never_pushes_clean_domain_above_low_risk():
    """Requirement (g): geo data alone can never push a clean domain above 'low risk'."""
    # Scan a verified clean destination URL (e.g. Wikipedia)
    report = scan_url("https://en.wikipedia.org/wiki/Computer_security")

    assert report["status"] in ("SAFE", "INCONCLUSIVE")
    # Risk score must remain low risk (0-29)
    assert report["score"] < 30
    assert report["level"] in ("Low Risk", "Inconclusive")

    # Assert that network report schema is fully populated
    assert "network" in report
    assert "hosts" in report["network"]
    assert "countries_in_path" in report["network"]
    assert "summary" in report["network"]
    assert len(report["network"]["summary"]) > 0


def test_brand_country_mismatch_fires_only_on_lookalikes():
    """Lookalike signal integration: country mismatch only fires when lookalike is active."""
    net_report = {
        "hosts": [{
            "host": "paypal-login-alert.top",
            "hop_index": 0,
            "role": "final",
            "ips": [{"ip": "185.220.101.4", "country_code": "RU", "city": "Moscow", "org": "Dynadot", "asn": "AS12345"}],
            "ttl": 300,
            "a_record_count": 1
        }],
        "countries_in_path": ["RU"],
        "summary": "Hosted in Russia."
    }

    # Case 1: Lookalike flag is FALSE -> No mismatch signal
    signals_benign = evaluate_network_signals(net_report, context_flags={"is_lookalike": False})
    assert not any(s["id"] == "brand_country_jurisdiction_mismatch" for s in signals_benign)

    # Case 2: Lookalike flag is TRUE -> Fires low (+8) mismatch signal
    signals_lookalike = evaluate_network_signals(net_report, context_flags={"is_lookalike": True})
    mismatch = [s for s in signals_lookalike if s["id"] == "brand_country_jurisdiction_mismatch"]
    assert len(mismatch) == 1
    assert mismatch[0]["severity"] == "low"
    assert mismatch[0]["score_impact"] == 8

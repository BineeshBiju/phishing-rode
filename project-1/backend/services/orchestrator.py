# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
CyberScape Unified Threat Scanning Orchestrator
Executes parallel multi-source threat intelligence checks (URLhaus, VirusTotal, Safe Browsing,
OpenPhish, RDAP, TLS, SSRF redirect tracing, heuristics, and AI domain classification)
with a 10-minute cache and 6-8s worker timeouts.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse
import time

from backend.services.normalizer import normalize_url, InvalidURLError
from backend.services.redirects import trace_redirects
from backend.services.urlhaus import query_urlhaus
from backend.services.safebrowsing import query_safebrowsing
from backend.services.virustotal import query_virustotal
from backend.services.openphish import query_openphish
from backend.services.domain_intel import get_domain_intelligence
from backend.services.heuristics import evaluate_heuristics
from backend.services.static_analysis import fetch_and_analyze_page
from backend.services.scoring import compute_scan_score, verdict_from_score
from services.network_intel import build_network_report, evaluate_network_signals, clear_geo_cache
from backend.services.history_service import format_url_findings_and_checks

SCAN_CACHE = {}  # url -> (timestamp, report_dict)
CACHE_TTL_SECONDS = 600  # 10 minutes


def clear_scan_cache():
    """Clear memory cache (useful for test isolation)."""
    SCAN_CACHE.clear()
    clear_geo_cache()


def scan_url(raw_url: str, bypass_cache: bool = False) -> dict:
    """
    Main entry point for scanning any destination URL.
    Used uniformly across URL Scanner, QR Scanner, and Email Analyzer.
    """
    cleaned = (raw_url or "").strip()
    if not cleaned:
        return {
            "url": cleaned,
            "final_url": cleaned,
            "score": 0,
            "status": "INVALID",
            "level": "No Result",
            "confidence": 0,
            "signals": [],
            "reasons": ["No URL provided for analysis."],
            "threat_intel": {},
            "redirect_chain": {"hops_count": 0, "chain": []},
            "geo_ip": {},
            "network": {"hosts": [], "countries_in_path": [], "summary": "No network destination to trace."},
            "ml_analysis": {}
        }

    # 1. Check 10-minute cache
    now = time.time()
    if not bypass_cache and cleaned in SCAN_CACHE:
        ts, cached_report = SCAN_CACHE[cleaned]
        if now - ts < CACHE_TTL_SECONDS:
            return cached_report

    # 2. Normalize and validate URL
    try:
        norm = normalize_url(cleaned)
    except InvalidURLError as err:
        return {
            "url": cleaned,
            "final_url": cleaned,
            "score": 0,
            "status": "INVALID",
            "level": "No Result",
            "confidence": 0,
            "signals": [{
                "id": "invalid_url_syntax",
                "source": "URL Normalizer",
                "severity": "critical",
                "score_impact": 0,
                "evidence": str(err)
            }],
            "reasons": [str(err)],
            "threat_intel": {},
            "redirect_chain": {"hops_count": 0, "chain": []},
            "geo_ip": {},
            "network": {"hosts": [], "countries_in_path": [], "summary": "No network destination to trace."},
            "ml_analysis": {}
        }

    normalized_url = norm["normalized_url"]

    # 3. SSRF-Safe Redirect Sandbox Tracer (follows up to 10 hops, blocking private IPs)
    redirect_data = trace_redirects(normalized_url, max_hops=10, timeout_per_hop=5.0)
    final_destination = redirect_data.get("final_url") or normalized_url
    is_ssrf_blocked = any(s.get("id") == "ssrf_blocked" for s in redirect_data.get("signals", []))

    # 4. Run threat feeds and analysis sources IN PARALLEL with ThreadPoolExecutor
    sources_checked = {}
    signals = list(redirect_data.get("signals", []))

    urlhaus_result = {}
    safebrowsing_result = {}
    virustotal_result = {}
    openphish_result = {}
    domain_intel_result = {}
    heuristics_result = {}
    static_analysis_result = {}
    network_report = {"hosts": [], "countries_in_path": [], "summary": "No network destination to trace."}

    if not is_ssrf_blocked:
        with ThreadPoolExecutor(max_workers=8) as executor:
            future_urlhaus = executor.submit(query_urlhaus, final_destination, 6.0)
            future_safebrowsing = executor.submit(query_safebrowsing, final_destination, 5.0)
            future_virustotal = executor.submit(query_virustotal, final_destination, 6.0)
            future_openphish = executor.submit(query_openphish, final_destination)
            future_domain_intel = executor.submit(get_domain_intelligence, final_destination)
            future_heuristics = executor.submit(evaluate_heuristics, final_destination)
            future_static_analysis = executor.submit(fetch_and_analyze_page, final_destination, 4.0)
            future_network = executor.submit(build_network_report, redirect_data, final_destination)

            # Wait for URLhaus
            try:
                urlhaus_result = future_urlhaus.result(timeout=7.0)
            except Exception:
                urlhaus_result = {"source": "URLhaus", "status": "UNAVAILABLE", "available": False, "reason": "Query timed out."}

            # Wait for Safe Browsing
            try:
                safebrowsing_result = future_safebrowsing.result(timeout=6.0)
            except Exception:
                safebrowsing_result = {"source": "Google Safe Browsing", "status": "UNAVAILABLE", "available": False, "reason": "Query timed out."}

            # Wait for VirusTotal
            try:
                virustotal_result = future_virustotal.result(timeout=7.0)
            except Exception:
                virustotal_result = {"source": "VirusTotal", "status": "UNAVAILABLE", "available": False, "reason": "Query timed out."}

            # Wait for OpenPhish
            try:
                openphish_result = future_openphish.result(timeout=4.0)
            except Exception:
                openphish_result = {"source": "OpenPhish", "status": "UNAVAILABLE", "available": False, "reason": "Query timed out."}

            # Wait for Domain Intel (DNS, TLS, RDAP, Geo-IP)
            try:
                domain_intel_result = future_domain_intel.result(timeout=6.0)
            except Exception:
                domain_intel_result = {"geo_ip": {}, "signals": []}

            # Wait for Heuristics & AI Model
            try:
                heuristics_result = future_heuristics.result(timeout=6.0)
            except Exception:
                heuristics_result = {"signals": [], "ml": {}}

            # Wait for Static HTML Analysis
            try:
                static_analysis_result = future_static_analysis.result(timeout=5.0)
            except Exception:
                static_analysis_result = {
                    "status": "unavailable",
                    "title": "",
                    "has_password_field": False,
                    "cross_domain_forms": [],
                    "hidden_iframes_count": 0,
                    "js_obfuscation": [],
                    "impersonated_brand": None,
                    "findings_summary": [],
                    "signals": []
                }

            # Wait for Network Intelligence
            try:
                network_report = future_network.result(timeout=6.0)
            except Exception:
                network_report = build_network_report(redirect_data, final_destination)
    else:
        static_analysis_result = {
            "status": "ssrf_blocked",
            "title": "",
            "has_password_field": False,
            "cross_domain_forms": [],
            "hidden_iframes_count": 0,
            "js_obfuscation": [],
            "impersonated_brand": None,
            "findings_summary": ["Static page fetch blocked by SSRF Guard."],
            "signals": []
        }
        network_report = build_network_report(redirect_data, final_destination)

    # Extract contextual evaluation flags
    is_lookalike = bool(heuristics_result.get("lookalike", {}).get("is_lookalike") or norm.get("has_punycode"))
    has_shortener = redirect_data.get("has_shortener", False)
    is_young = any(s.get("id") == "young_domain" for s in signals)

    context_flags = {
        "is_ssrf_blocked": is_ssrf_blocked,
        "is_lookalike": is_lookalike,
        "has_shortener": has_shortener,
        "is_young_domain": is_young
    }

    # Record sources checked state
    has_geo = bool(
        domain_intel_result.get("geo_ip", {}).get("status") not in (None, "error")
        or (network_report and network_report.get("hosts") and any(ip.get("status") in ("ok", "blocked_private_ip") for h in network_report.get("hosts", []) for ip in h.get("ips", [])))
    )

    sources_checked = {
        "urlhaus": {
            "name": "URLhaus Feed",
            "status": urlhaus_result.get("status", "UNAVAILABLE"),
            "available": urlhaus_result.get("available", False)
        },
        "safebrowsing": {
            "name": "Google Safe Browsing",
            "status": safebrowsing_result.get("status", "UNAVAILABLE"),
            "available": safebrowsing_result.get("available", False)
        },
        "virustotal": {
            "name": "VirusTotal",
            "status": virustotal_result.get("status", "UNAVAILABLE"),
            "available": virustotal_result.get("available", False)
        },
        "openphish": {
            "name": "OpenPhish",
            "status": openphish_result.get("status", "UNAVAILABLE"),
            "available": openphish_result.get("available", False)
        },
        "domain_intel": {
            "name": "DNS & Geo-IP",
            "status": "OK" if has_geo else "UNAVAILABLE",
            "available": has_geo
        },
        "static_analysis": {
            "name": "Static HTML Analysis",
            "status": "OK" if static_analysis_result.get("status") == "analyzed" else ("SKIPPED" if static_analysis_result.get("status") in ("skipped_non_html", "ssrf_blocked") else "UNAVAILABLE"),
            "available": static_analysis_result.get("status") == "analyzed"
        }
    }

    # Aggregate signals
    if urlhaus_result.get("signal"):
        signals.append(urlhaus_result["signal"])
    if safebrowsing_result.get("signal"):
        signals.append(safebrowsing_result["signal"])
    if virustotal_result.get("signal"):
        signals.append(virustotal_result["signal"])
    if openphish_result.get("signal"):
        signals.append(openphish_result["signal"])
    if domain_intel_result.get("signals"):
        signals.extend(domain_intel_result["signals"])
    if heuristics_result.get("signals"):
        signals.extend(heuristics_result["signals"])
    if static_analysis_result.get("signals"):
        signals.extend(static_analysis_result["signals"])

    # Evaluate network intelligence signals
    network_signals = evaluate_network_signals(network_report, context_flags)
    signals.extend(network_signals)

    # 5. Compute unified score, verdict, and confidence
    score_result = compute_scan_score(signals, sources_checked, context_flags)

    # 6. Build legacy-compatible reasons and threat_intel structures
    reasons = []
    if urlhaus_result.get("reason"):
        reasons.append(urlhaus_result["reason"])
    for sig in signals:
        if sig.get("severity") in ("critical", "warning") and sig.get("evidence"):
            if sig["evidence"] not in reasons:
                reasons.append(sig["evidence"])

    if not reasons:
        reasons.append("Threat intelligence databases and heuristic models verified destination as clean.")

    vt_flagged = virustotal_result.get("flagged", 0)
    vt_total = virustotal_result.get("total_engines", 90)

    threat_intel_payload = {
        "flagged_engines": vt_flagged,
        "total_engines": vt_total,
        "summary": f"{vt_flagged}/{vt_total} Engines Flagged",
        "status": score_result["status"],
        "scan_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "urlhaus": urlhaus_result,
        "safebrowsing": safebrowsing_result,
        "virustotal": virustotal_result,
        "openphish": openphish_result
    }

    geo_data = domain_intel_result.get("geo_ip") or {}
    if (not geo_data or geo_data.get("status") == "error") and network_report.get("hosts"):
        final_ips = network_report["hosts"][-1].get("ips", [])
        if final_ips:
            f_ip = final_ips[0]
            geo_data = {
                "ip": f_ip.get("ip"),
                "country": f_ip.get("country"),
                "country_code": f_ip.get("country_code"),
                "city": f_ip.get("city"),
                "region": f_ip.get("region"),
                "isp": f_ip.get("isp"),
                "org": f_ip.get("org"),
                "asn": f_ip.get("asn"),
                "latitude": f_ip.get("lat"),
                "longitude": f_ip.get("lon"),
                "coordinates": f"{f_ip.get('lat')}, {f_ip.get('lon')}",
                "status": "success" if f_ip.get("status") == "ok" else "error"
            }

    ml_analysis = heuristics_result.get("ml") or {}

    report = {
        "url": cleaned,
        "final_url": final_destination,
        "domain": urlparse(final_destination).hostname or urlparse(cleaned).hostname or "",
        "host": urlparse(final_destination).hostname or urlparse(cleaned).hostname or "",
        "score": score_result["score"],
        "status": score_result["status"],
        "level": score_result["level"],
        "verdict": score_result["verdict"],
        "confidence": score_result["confidence"],
        "signals": signals,
        "reasons": reasons,
        "sources_checked": sources_checked,
        "threat_intel": threat_intel_payload,
        "ml_analysis": ml_analysis,
        "static_analysis": static_analysis_result,
        "geo_ip": geo_data,
        "network": network_report,
        "redirect_chain": redirect_data,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Populate structured problem findings, verified passed checks, and technical details
    findings, passed_checks, technical = format_url_findings_and_checks(report)
    report["findings"] = findings
    report["passed_checks"] = passed_checks
    report["technical_details"] = technical

    # Cache report
    SCAN_CACHE[cleaned] = (now, report)
    return report


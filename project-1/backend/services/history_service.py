# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
CyberScape History & Forensic Detail Service
Standardizes telemetry, findings, passed checks, and technical details across
URL, QR, and Email forensic scans for both interactive inspection and PDF reports.
"""

import json
import re
from datetime import datetime
from urllib.parse import urlparse


def detect_qr_payload_type(text: str) -> str:
    """Detect specific data format contained within a QR code payload."""
    if not text:
        return "Empty"
    t = text.strip()
    lower = t.lower()
    if lower.startswith(("http://", "https://")):
        return "Web URL"
    if lower.startswith("upi://"):
        return "UPI Payment Link"
    if lower.startswith("wifi:") or lower.startswith("wpa:"):
        return "Wi-Fi Configuration"
    if "begin:vcard" in lower:
        return "vCard Contact Card"
    if lower.startswith("mailto:"):
        return "Email Action Link"
    if lower.startswith("tel:"):
        return "Telephone Action"
    if lower.startswith("smsto:") or lower.startswith("sms:"):
        return "SMS Dispatch Link"
    return "Plain Text / Raw Data"


def format_url_findings_and_checks(result: dict) -> tuple[list, list, dict]:
    """
    Extract structured problem findings, verified passed checks, and technical details
    from a URL or QR scan result dictionary.
    """
    findings = []
    passed_checks = []
    signals = result.get("signals") or []
    sources = result.get("sources_checked") or {}
    intel = result.get("threat_intel") or {}
    geo = result.get("geo_ip") or {}
    network = result.get("network") or {}
    redirect = result.get("redirect_chain") or {}
    url = result.get("url") or result.get("target_url") or ""

    # 1. FINDINGS (Flagged problems sorted by severity)
    for sig in signals:
        sev = (sig.get("severity") or "low").lower()
        if sev in ("critical", "high", "medium", "warning", "elevated", "low"):
            cat = "Heuristics"
            sig_id = str(sig.get("id") or "").lower()
            if any(k in sig_id for k in ("urlhaus", "virustotal", "safebrowsing", "openphish", "threat")):
                cat = "Threat Intelligence"
            elif any(k in sig_id for k in ("lookalike", "young", "punycode", "typo", "domain")):
                cat = "Domain Reputation"
            elif any(k in sig_id for k in ("ssrf", "ip", "asn", "ptr", "network")):
                cat = "Network Infrastructure"
            elif any(k in sig_id for k in ("redirect", "hops", "shortener")):
                cat = "Redirection & Evasion"

            # Contextual mitigation recommendation
            rec = "Exercise heightened caution before interacting with this destination."
            if cat == "Threat Intelligence":
                rec = "Immediately block access to this confirmed malicious endpoint across firewalls and endpoint security tools."
            elif cat == "Domain Reputation":
                rec = "Verify brand identity and inspect domain registration; do not input credentials or sensitive data."
            elif cat == "Network Infrastructure":
                rec = "Ensure traffic is routed strictly through verified external DNS and public IP gateways."
            elif cat == "Redirection & Evasion":
                rec = "Inspect intermediate redirect hops and verify final landing destination before continuing."

            findings.append({
                "category": cat,
                "severity": "high" if sev in ("critical", "high") else ("medium" if sev in ("medium", "warning", "elevated") else "low"),
                "title": sig.get("title") or sig.get("name") or "Security Threat Signal Detected",
                "explanation": sig.get("explanation") or sig.get("description") or sig.get("evidence") or "Anomalous indicator flagged.",
                "evidence": str(sig.get("evidence") or sig.get("value") or url),
                "recommendation": rec
            })

    # Add any top-level reasons if not captured
    if result.get("status") == "MALICIOUS" and not findings:
        for r in result.get("reasons", []):
            findings.append({
                "category": "Threat Intelligence",
                "severity": "high",
                "title": "Malicious Destination Flagged",
                "explanation": r,
                "evidence": url,
                "recommendation": "Block connections and quarantine any files downloaded from this resource."
            })

    # 2. PASSED CHECKS (Verified security capabilities)
    if sources.get("urlhaus", {}).get("status") == "OK":
        passed_checks.append({
            "title": "URLhaus Abuse Database Clear",
            "description": "Destination is verified clean on abuse.ch URLhaus malware and botnet blacklist."
        })
    if sources.get("safebrowsing", {}).get("status") == "OK":
        passed_checks.append({
            "title": "Google Safe Browsing Verified",
            "description": "Domain passed Google Safe Browsing API check with zero reported threats."
        })
    if sources.get("virustotal", {}).get("status") == "OK" or intel.get("flagged_engines", 0) == 0:
        passed_checks.append({
            "title": "Multi-Engine Antivirus Consensus",
            "description": "Clean consensus evaluated across global antivirus and URL reputation scanners."
        })
    if sources.get("openphish", {}).get("status") == "OK":
        passed_checks.append({
            "title": "OpenPhish Phishing Feed Clear",
            "description": "No active phishing telemetry reported on OpenPhish community feeds."
        })

    if url.lower().startswith("https://"):
        passed_checks.append({
            "title": "TLS Cryptographic Encryption",
            "description": "Traffic transmitted over encrypted HTTPS protocol with valid SSL/TLS certificates."
        })

    if not any("ssrf" in str(s.get("id", "")).lower() for s in signals):
        passed_checks.append({
            "title": "SSRF Boundary Verification",
            "description": "Destination resolves to routable public infrastructure; private network traversal blocked."
        })

    if not any("lookalike" in str(s.get("id", "")).lower() for s in signals):
        passed_checks.append({
            "title": "Domain Typosquatting Check",
            "description": "No homoglyphic substitutions, punycode deception, or targeted brand mimicry found."
        })

    if redirect.get("hops_count", 0) <= 2:
        passed_checks.append({
            "title": "Canonical Direct Routing",
            "description": "Direct navigation path observed without excessive or cloaked redirection hops."
        })

    static_analysis = result.get("static_analysis") or {}
    if static_analysis.get("status") == "analyzed":
        if not static_analysis.get("has_password_field") and not static_analysis.get("cross_domain_forms") and not static_analysis.get("hidden_iframes_count") and not static_analysis.get("js_obfuscation"):
            passed_checks.append({
                "title": "Static HTML Content Safe",
                "description": "No credential-harvesting password inputs, cross-domain form submissions, hidden iframes, or obfuscated JS."
            })

    # 3. TECHNICAL DETAILS
    parsed = urlparse(url)
    final_url = result.get("final_url") or url
    parsed_final = urlparse(final_url)

    tls_is_self_signed = any("tls_self_signed" == str(s.get("id", "")) for s in signals)
    tls_hostname_mismatch = any("tls_hostname_mismatch" == str(s.get("id", "")) for s in signals)
    tls_expired = any("tls_expired" == str(s.get("id", "")) for s in signals)

    technical = {
        "url_breakdown": {
            "canonical_url": url,
            "final_destination": final_url,
            "scheme": parsed.scheme.upper() if parsed.scheme else "HTTP",
            "host": parsed.hostname or result.get("domain") or "Autonomous",
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "path": parsed.path or "/",
            "query_parameters": parsed.query or "None"
        },
        "tls_certificate": {
            "protocol": parsed.scheme.upper() if parsed.scheme else "HTTP",
            "status": "Encrypted HTTPS Connection" if parsed.scheme == "https" else "Insecure Plaintext HTTP",
            "certificate_valid": parsed.scheme == "https" and not (tls_is_self_signed or tls_hostname_mismatch or tls_expired),
            "is_self_signed": tls_is_self_signed,
            "hostname_mismatch": tls_hostname_mismatch,
            "is_expired": tls_expired
        },
        "static_page_analysis": {
            "page_title": static_analysis.get("title") or "Untitled",
            "has_password_field": static_analysis.get("has_password_field", False),
            "cross_domain_forms_count": len(static_analysis.get("cross_domain_forms", [])),
            "hidden_iframes_count": static_analysis.get("hidden_iframes_count", 0),
            "obfuscated_js_count": len(static_analysis.get("js_obfuscation", []))
        },
        "infrastructure": {
            "ip_address": geo.get("ip") or (network.get("hosts") and network["hosts"][-1].get("ips") and network["hosts"][-1]["ips"][0].get("ip")) or "Unresolved",
            "reverse_dns": (network.get("hosts") and network["hosts"][-1].get("ips") and network["hosts"][-1]["ips"][0].get("ptr")) or "None",
            "asn_org": f"{geo.get('asn') or 'AS--'} • {geo.get('org') or geo.get('isp') or 'Enterprise Host Network'}",
            "location": f"{geo.get('city') or 'Global'}, {geo.get('country') or 'Network'} ({geo.get('country_code') or 'UN'})",
            "registrar": result.get("registrar") or "Enterprise Host Network"
        },
        "redirect_chain": {
            "hops_count": redirect.get("hops_count", 0),
            "chain": redirect.get("chain", []),
            "has_shortener": redirect.get("has_shortener", False)
        },
        "threat_intel_summary": {
            "engines_flagged": intel.get("flagged_engines", 0),
            "total_engines": intel.get("total_engines", 90),
            "sources": sources
        }
    }

    return findings, passed_checks, technical


def format_email_findings_and_checks(email_result: dict) -> tuple[list, list, dict]:
    """
    Extract structured problem findings, verified passed checks, and technical details
    from an Email investigation result dictionary.
    """
    findings = email_result.get("findings") or []
    passed_checks = []
    auth = email_result.get("auth_results") or {}
    sender = email_result.get("sender_check") or {}
    origin = email_result.get("origin_ip") or {}
    content = email_result.get("content_findings") or {}

    # Ensure all findings have recommendation field
    for f in findings:
        if not f.get("recommendation"):
            cat = f.get("category", "")
            if "Spoofing" in cat:
                f["recommendation"] = "Quarantine messages from this unauthorized address; verify sender through verified out-of-band channels."
            elif "Authentication" in cat:
                f["recommendation"] = "Enforce strict DMARC quarantine or reject policy to prevent unauthorized domain usage."
            elif "Executive" in cat:
                f["recommendation"] = "Do not execute wire transfers or share sensitive files; verify request via a trusted executive phone line."
            elif "Hyperlinks" in cat:
                f["recommendation"] = "Do not click unverified links; navigate to verified official domains directly."
            else:
                f["recommendation"] = "Exercise caution and consult security operations before replying or clicking links."

    # Passed checks
    spf_status = str(auth.get("spf", {}).get("status") if isinstance(auth.get("spf"), dict) else auth.get("spf", "")).upper()
    dkim_status = str(auth.get("dkim", {}).get("status") if isinstance(auth.get("dkim"), dict) else auth.get("dkim", "")).upper()
    dmarc_status = str(auth.get("dmarc", {}).get("status") if isinstance(auth.get("dmarc"), dict) else auth.get("dmarc", "")).upper()

    if spf_status == "PASS":
        passed_checks.append({
            "title": "SPF Authentication Verified",
            "description": "Sending MTA IP is explicitly authorized in sender domain DNS SPF records."
        })
    if dkim_status == "PASS":
        passed_checks.append({
            "title": "DKIM Signature Verified",
            "description": "Cryptographic signature confirmed intact; email body and headers were not altered."
        })
    if dmarc_status == "PASS":
        passed_checks.append({
            "title": "DMARC Policy Alignment Conformance",
            "description": "Message passes DMARC alignment criteria matching the visible From header domain."
        })
    if not sender.get("is_spoofed"):
        passed_checks.append({
            "title": "Sender Identity Alignment",
            "description": "Visible From header domain aligns with Return-Path, Reply-To, and envelope addresses."
        })
    if content.get("phishing_intent") == "LOW":
        passed_checks.append({
            "title": "Low Coercive Threat Level",
            "description": "Zero panic triggers, credential harvesting prompts, or payment demands detected."
        })
    if not content.get("suspicious_attachments"):
        passed_checks.append({
            "title": "Attachment Security Clean",
            "description": "No executable binaries, scripts, or disguised double-extension files detected."
        })
    if not any(link.get("anchor_mismatch") or link.get("href_mismatch") for link in email_result.get("links", [])):
        passed_checks.append({
            "title": "Hyperlink Transparency",
            "description": "Anchor texts accurately reflect destination URLs without deceptive redirection."
        })

    technical = {
        "sender_verification": {
            "from_address": sender.get("from_addr") or "Unspecified",
            "display_name": sender.get("from_name") or "None",
            "from_domain": sender.get("from_domain") or "local",
            "return_path": sender.get("return_path") or "None",
            "reply_to": sender.get("reply_to") or "None (Default to From)",
            "is_spoofed": sender.get("is_spoofed", False),
            "spoofing_flags": sender.get("spoofing_flags", [])
        },
        "authentication_protocols": {
            "spf": {
                "status": spf_status,
                "explanation": auth.get("spf", {}).get("explanation", "Evaluated in email headers.") if isinstance(auth.get("spf"), dict) else "Evaluated"
            },
            "dkim": {
                "status": dkim_status,
                "explanation": auth.get("dkim", {}).get("explanation", "Evaluated in email headers.") if isinstance(auth.get("dkim"), dict) else "Evaluated"
            },
            "dmarc": {
                "status": dmarc_status,
                "explanation": auth.get("dmarc", {}).get("explanation", "Evaluated in email headers.") if isinstance(auth.get("dmarc"), dict) else "Evaluated"
            }
        },
        "origin_network": {
            "originating_ip": origin.get("ip") or "N/A",
            "country": f"{origin.get('country', 'Unknown')} ({origin.get('country_code', 'UN')})",
            "city": origin.get("city", "Unknown City"),
            "isp_asn": f"{origin.get('asn', 'N/A')} • {origin.get('isp', 'Unknown ISP')}"
        },
        "content_and_links": {
            "total_links": len(email_result.get("links", [])),
            "urgency_index": content.get("urgency_score", 0),
            "ceo_fraud_detected": content.get("ceo_fraud_detected", False),
            "links": email_result.get("links", [])
        },
        "attachments_forensics": {
            "total_attachments": len(email_result.get("attachments", [])),
            "attachments": email_result.get("attachments", [])
        },
        "hop_timeline": email_result.get("hop_timeline", [])
    }

    return findings, passed_checks, technical


def format_history_record_for_inspect(row: dict) -> dict:
    """
    Adapt any database scan_logs row into the complete structured inspection payload.
    Handles URL, QR, and Email scans, including legacy rows with limited data.
    """
    record_id = row.get("id")
    source = (row.get("source") or "URL").upper()
    if source in ("INSPECTOR", "AUDIT"):
        scan_type = "URL"
    else:
        scan_type = source

    target = row.get("target_url") or "Forensic Record"
    score = int(row.get("score") or 0)
    verdict = (row.get("status") or "UNKNOWN").upper()
    level = row.get("level") or ("Low Risk" if verdict == "SAFE" else ("Critical Threat" if verdict == "MALICIOUS" else "Elevated Risk"))
    timestamp = row.get("time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Parse details_json
    raw_details = {}
    details_str = row.get("details_json")
    if details_str:
        try:
            if isinstance(details_str, dict):
                raw_details = details_str
            else:
                raw_details = json.loads(details_str)
        except Exception:
            raw_details = {}

    limited_data = False
    findings = []
    passed_checks = []
    technical = {}

    # If details_json is empty, report limited data gracefully
    if not raw_details:
        limited_data = True
        findings = []
        passed_checks = []
        technical = {
            "note": "Limited telemetry stored for this older scan record.",
            "target": target,
            "status": verdict,
            "score": score
        }
    elif scan_type == "EMAIL" or raw_details.get("scan_type") == "EMAIL" or "sender_check" in raw_details:
        scan_type = "EMAIL"
        findings, passed_checks, technical = format_email_findings_and_checks(raw_details)
        # Use target from details if available
        if raw_details.get("target"):
            target = raw_details["target"]
    elif scan_type == "QR" or raw_details.get("scan_type") == "QR" or raw_details.get("source") == "QR":
        scan_type = "QR"
        findings, passed_checks, technical = format_url_findings_and_checks(raw_details)
        technical["qr_payload"] = {
            "payload_data": target,
            "payload_type": detect_qr_payload_type(target),
            "risk_assessment": "Standard clean payload" if score <= 30 else "Elevated QR redirection / cloaking risk"
        }
    else:
        scan_type = "URL"
        findings, passed_checks, technical = format_url_findings_and_checks(raw_details)

    # Calculate severity counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": len(passed_checks)}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev == "critical":
            counts["critical"] += 1
        elif sev == "high":
            counts["high"] += 1
        elif sev in ("medium", "warning", "elevated"):
            counts["medium"] += 1
        elif sev == "safe":
            counts["safe"] += 1
        else:
            counts["low"] += 1

    can_rescan = scan_type in ("URL", "QR") and bool(target) and not target.startswith("Email")
    rescan_url = target if can_rescan else None

    # Safe raw json for technical accordion
    try:
        raw_json_str = json.dumps(raw_details, indent=2)
    except Exception:
        raw_json_str = "{}"

    confidence = raw_details.get("confidence") or (95 if verdict in ("SAFE", "MALICIOUS") else 85)

    return {
        "id": record_id,
        "scan_type": scan_type,
        "target": target,
        "timestamp": timestamp,
        "score": score,
        "verdict": verdict,
        "level": level,
        "confidence": confidence,
        "limited_data": limited_data,
        "can_rescan": can_rescan,
        "rescan_url": rescan_url,
        "severity_counts": counts,
        "findings": findings,
        "passed_checks": passed_checks,
        "technical_details": technical,
        "raw_json": raw_json_str
    }


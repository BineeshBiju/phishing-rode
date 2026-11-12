# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
CyberScape QR Code Deep Security Analyzer
Supports:
1. Payload type detection: URL, UPI (upi://pay), WiFi, SMS, mailto, vCard, plain text
2. Deep UPI security analysis: pa, pn, am, cu parsing, pre-filled amounts,
   payee name vs VPA mismatch, and collect-request / refund deception patterns
3. Non-URL payload security inspection (WiFi unencrypted, SMS phishing links, mailto spoofing)
4. Full URL scanner pipeline routing for web destinations
"""

from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
import re

from backend.services.orchestrator import scan_url
from backend.services.scoring import verdict_from_score, evaluate_risk
from backend.services.history_service import format_url_findings_and_checks


# Institutional / Enterprise keywords commonly impersonated in payment scams
INSTITUTIONAL_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis", "pnb", "bob", "bank", "electricity",
    "water", "bill", "energy", "bescom", "tneb", "mseb", "uppcl", "refund",
    "support", "care", "helpline", "official", "department", "customs",
    "tax", "income tax", "police", "kyc", "verification", "airtel", "jio",
    "bsnl", "vi", "vodafone", "amazon", "flipkart", "paytm", "phonepe",
    "gpay", "google pay", "lottery", "prize", "cashback", "reward"
]

COLLECT_DECEPTION_KEYWORDS = [
    "receive", "refund", "cashback", "cash back", "reward", "prize", "claim",
    "credit", "accept", "won", "winner", "bonus", "lottery", "credited",
    "get money", "collect payment", "receive money"
]


def detect_qr_payload_type(raw_text: str) -> str:
    """
    Classify QR payload into exact supported types:
    URL, UPI, WiFi, SMS, mailto, vCard, plain text
    """
    if not raw_text:
        return "plain text"

    text = raw_text.strip()
    lower = text.lower()

    # 1. UPI payment link
    if lower.startswith("upi://pay") or lower.startswith("upi://"):
        return "UPI"

    # 2. Web URL
    if lower.startswith(("http://", "https://", "ftp://")):
        return "URL"
    if re.match(r"^(www\.)[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(/.*)?$", text, re.IGNORECASE):
        return "URL"

    # 3. Wi-Fi configuration
    if lower.startswith("wifi:") or lower.startswith("wpa:"):
        return "WiFi"

    # 4. SMS message dispatch
    if lower.startswith("smsto:") or lower.startswith("sms:"):
        return "SMS"

    # 5. Email action
    if lower.startswith("mailto:"):
        return "mailto"

    # 6. vCard contact
    if "begin:vcard" in lower or lower.startswith("mecard:"):
        return "vCard"

    # 7. Plain text / fallback
    return "plain text"


def parse_upi_uri(uri: str) -> dict:
    """
    Parse NPCI UPI payment URI parameters: pa, pn, am, cu, tn, tr, mc, mode.
    """
    parsed = urlparse(uri)
    query_str = parsed.query or (uri.split("?", 1)[1] if "?" in uri else "")
    qs = parse_qs(query_str, keep_blank_values=True)

    def get_single(key, default=""):
        vals = qs.get(key, [])
        return vals[0].strip() if vals else default

    pa = unquote(get_single("pa"))
    pn = unquote(get_single("pn"))
    am_str = get_single("am")
    cu = get_single("cu", "INR").upper() or "INR"
    tn = unquote(get_single("tn"))
    mc = get_single("mc")
    tr = get_single("tr")
    mode = get_single("mode")

    amount = None
    if am_str:
        try:
            amount = float(re.sub(r"[^\d.]", "", am_str))
        except (ValueError, TypeError):
            amount = None

    return {
        "raw_uri": uri,
        "pa": pa,
        "pn": pn,
        "am": amount,
        "am_str": am_str,
        "cu": cu,
        "tn": tn,
        "mc": mc,
        "tr": tr,
        "mode": mode
    }


def analyze_upi_payload(uri: str) -> dict:
    """
    Perform deep security analysis of a UPI payment QR payload:
    1. Parse pa, pn, am, cu
    2. Flag pre-filled amounts
    3. Flag payee name vs VPA mismatch
    4. Flag collect-request & refund deception patterns
    """
    params = parse_upi_uri(uri)
    pa = params["pa"]
    pn = params["pn"]
    am = params["am"]
    cu = params["cu"]
    tn = params["tn"]
    mode = params["mode"]

    signals = []
    reasons = []
    score = 0
    has_critical = False
    has_warning = False

    # 1. Validation of VPA presence and format
    if not pa:
        signals.append({
            "id": "upi_missing_vpa",
            "source": "UPI Protocol Analyzer",
            "severity": "critical",
            "score_impact": 50,
            "evidence": "UPI QR payload is missing mandatory 'pa' (Payee Address) parameter."
        })
        reasons.append("Malformed UPI QR: missing Payee Address (pa).")
        has_critical = True
    elif "@" not in pa:
        signals.append({
            "id": "upi_malformed_vpa",
            "source": "UPI Protocol Analyzer",
            "severity": "warning",
            "score_impact": 25,
            "evidence": f"VPA '{pa}' does not follow the standard handle@bank PSP structure."
        })
        reasons.append(f"VPA format anomaly: '{pa}' lacks standard bank handle suffix.")
        has_warning = True

    # 2. Pre-filled amount analysis
    if am is not None and am > 0:
        if am >= 5000:
            signals.append({
                "id": "upi_high_prefilled_amount",
                "source": "Payment Verification",
                "severity": "critical",
                "score_impact": 45,
                "evidence": f"High pre-filled payment amount: ₹{am:,.2f} {cu}. Approving will immediately debit this large sum."
            })
            reasons.append(f"High pre-filled debit amount of ₹{am:,.2f} {cu} requested.")
            has_critical = True
            score += 45
        else:
            signals.append({
                "id": "upi_prefilled_amount",
                "source": "Payment Verification",
                "severity": "warning",
                "score_impact": 25,
                "evidence": f"Pre-filled payment amount: ₹{am:,.2f} {cu}. Scanning will prompt authorization of this fixed debit."
            })
            reasons.append(f"Fixed pre-filled debit amount: ₹{am:,.2f} {cu}.")
            has_warning = True
            score += 25

    # 3. Payee Name vs VPA Mismatch (Impersonation check)
    pn_lower = pn.lower()
    pa_lower = pa.lower()
    pa_handle = pa_lower.split("@")[0] if "@" in pa_lower else pa_lower

    impersonated_inst = None
    for kw in INSTITUTIONAL_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", pn_lower):
            impersonated_inst = kw
            break

    if impersonated_inst:
        # Check if the VPA handle legitimately represents this institution
        # Legitimate handles usually contain the institution's official brand
        if impersonated_inst not in pa_handle:
            signals.append({
                "id": "upi_payee_vpa_mismatch",
                "source": "Payee Identity Verification",
                "severity": "critical",
                "score_impact": 65,
                "evidence": f"Payee Name vs VPA Mismatch: Payee claims to be '{pn}' ({impersonated_inst.title()}), but payment routes to personal/unaffiliated address '{pa}'."
            })
            reasons.append(f"Brand impersonation detected: Payee claims '{pn}' but routes to '{pa}'.")
            has_critical = True
            score += 65

    # 4. Collect-Request / Refund Deception Patterns
    # Scammers trick victims into thinking scanning will CREDIT them money
    combined_notes = f"{tn} {pn}".lower()
    deception_detected = False
    deceptive_phrase = None

    for kw in COLLECT_DECEPTION_KEYWORDS:
        if kw in combined_notes:
            deception_detected = True
            deceptive_phrase = kw
            break

    if mode == "02" or "collect" in (params.get("tr") or "").lower():
        deception_detected = True
        deceptive_phrase = "Collect-Request Mode (02)"

    if deception_detected:
        signals.append({
            "id": "upi_collect_deception",
            "source": "Deception Heuristics",
            "severity": "critical",
            "score_impact": 85,
            "evidence": f"Collect / Refund Scam Pattern: QR references '{deceptive_phrase}'. Entering your UPI PIN ALWAYS transfers money OUT of your account; you never enter a PIN to receive money."
        })
        reasons.append("Fraudulent collect/refund pattern: falsely indicates receiving money.")
        has_critical = True
        score += 85

    # Clean check if no issues found
    if not has_critical and not has_warning:
        signals.append({
            "id": "upi_clean_structure",
            "source": "UPI Protocol Analyzer",
            "severity": "safe",
            "score_impact": -5,
            "evidence": f"Standard dynamic UPI payment request targeting '{pa}' ({pn or 'Verified Payee'})."
        })
        reasons.append("Verified UPI payment payload with standard parameter structure.")
        score = 0

    final_score = max(0, min(100, score))
    sources_checked = {
        "upi_protocol": {"name": "UPI Protocol Syntax", "status": "OK", "available": True},
        "payee_check": {"name": "Payee & VPA Alignment", "status": "FLAGGED" if any(s["id"] == "upi_payee_vpa_mismatch" for s in signals) else "OK", "available": True},
        "amount_check": {"name": "Transaction Amount Risk", "status": "FLAGGED" if am and am > 0 else "OK", "available": True},
        "deception_check": {"name": "Collect Scam Heuristics", "status": "FLAGGED" if deception_detected else "OK", "available": True}
    }
    risk_info = evaluate_risk(final_score, sources_checked=sources_checked, scan_type="QR", confidence=95)

    report = {
        "url": uri,
        "source": "QR",
        "payload_type": "UPI",
        "score": final_score,
        "status": risk_info["status"],
        "level": risk_info["level"],
        "verdict": risk_info["verdict_label"],
        "verdict_title": risk_info["verdict_title"],
        "confidence": risk_info["confidence"],
        "signals": signals,
        "reasons": reasons,
        "sources_checked": sources_checked,
        "upi_details": params,
        "redirect_chain": {"hops_count": 0, "chain": []},
        "geo_ip": {},
        "network": {
            "hosts": [],
            "countries_in_path": [],
            "summary": f"UPI Payment Link -> Payee: {pn or 'Merchant'} ({pa})"
        },
        "threat_intel": {
            "flagged_engines": 1 if final_score >= 70 else 0,
            "total_engines": 4,
            "summary": f"Risk Score {final_score}/100",
            "status": risk_info["status"]
        },
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    findings, passed_checks, technical = format_url_findings_and_checks(report)
    report["findings"] = findings
    report["passed_checks"] = passed_checks
    report["technical_details"] = technical
    return report


def parse_wifi_payload(raw: str) -> dict:
    """
    Parse WIFI:S:SSID;T:WPA;P:password;H:false;;
    """
    clean = raw.strip()
    if clean.upper().startswith("WIFI:"):
        clean = clean[5:]

    tokens = clean.split(";")
    data = {"ssid": "", "auth_type": "WPA", "password": "", "hidden": False}

    for tok in tokens:
        if not tok:
            continue
        if tok.startswith("S:"):
            data["ssid"] = tok[2:]
        elif tok.startswith("T:"):
            data["auth_type"] = tok[2:].upper()
        elif tok.startswith("P:"):
            data["password"] = tok[2:]
        elif tok.startswith("H:"):
            data["hidden"] = tok[2:].lower() in ("true", "1")

    return data


def analyze_wifi_payload(raw: str) -> dict:
    """Security inspection for Wi-Fi configurations."""
    wifi = parse_wifi_payload(raw)
    signals = []
    reasons = []
    score = 0

    if wifi["auth_type"] in ("NOPASS", "", "NONE"):
        signals.append({
            "id": "wifi_unencrypted",
            "source": "Wi-Fi Security Analyzer",
            "severity": "warning",
            "score_impact": 35,
            "evidence": f"Unencrypted Open Wi-Fi Network ('{wifi['ssid']}'). Traffic can be intercepted without encryption."
        })
        reasons.append("Open unencrypted Wi-Fi configuration.")
        score += 35
    elif wifi["auth_type"] == "WEP":
        signals.append({
            "id": "wifi_wep_deprecated",
            "source": "Wi-Fi Security Analyzer",
            "severity": "warning",
            "score_impact": 30,
            "evidence": f"Deprecated WEP encryption on network '{wifi['ssid']}'. WEP is vulnerable to rapid key cracking."
        })
        reasons.append("Deprecated WEP encryption detected.")
        score += 30
    else:
        signals.append({
            "id": "wifi_secure",
            "source": "Wi-Fi Security Analyzer",
            "severity": "safe",
            "score_impact": -5,
            "evidence": f"Encrypted Wi-Fi configuration ({wifi['auth_type']}) for network '{wifi['ssid']}'."
        })
        reasons.append(f"Standard {wifi['auth_type']} encrypted Wi-Fi configuration.")

    final_score = max(0, min(100, score))
    sources_checked = {
        "wifi_security": {"name": "Wi-Fi Encryption Check", "status": "OK", "available": True}
    }
    risk_info = evaluate_risk(final_score, sources_checked=sources_checked, scan_type="QR", confidence=90)

    report = {
        "url": raw,
        "source": "QR",
        "payload_type": "WiFi",
        "score": final_score,
        "status": risk_info["status"],
        "level": risk_info["level"],
        "verdict": risk_info["verdict_label"],
        "verdict_title": risk_info["verdict_title"],
        "confidence": risk_info["confidence"],
        "signals": signals,
        "reasons": reasons,
        "sources_checked": sources_checked,
        "wifi_details": wifi,
        "redirect_chain": {"hops_count": 0, "chain": []},
        "geo_ip": {},
        "network": {
            "hosts": [],
            "countries_in_path": [],
            "summary": f"Wi-Fi Network -> SSID: {wifi['ssid']} ({wifi['auth_type']})"
        },
        "threat_intel": {},
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    findings, passed_checks, technical = format_url_findings_and_checks(report)
    report["findings"] = findings
    report["passed_checks"] = passed_checks
    report["technical_details"] = technical
    return report


def analyze_general_payload(raw: str, payload_type: str) -> dict:
    """Analyze non-URL payloads (SMS, mailto, vCard, plain text)."""
    signals = []
    reasons = []
    score = 0
    extracted_urls = re.findall(r"https?://[^\s<>\"']+", raw)

    if extracted_urls:
        signals.append({
            "id": "payload_embedded_url",
            "source": "Payload Extractor",
            "severity": "warning",
            "score_impact": 20,
            "evidence": f"Payload contains embedded web hyperlink: {extracted_urls[0]}"
        })
        reasons.append(f"Embedded web link found: {extracted_urls[0]}")
        score += 20
    else:
        signals.append({
            "id": "payload_plain_content",
            "source": "Payload Inspector",
            "severity": "safe",
            "score_impact": 0,
            "evidence": f"Standard {payload_type} content without external execution threats."
        })
        reasons.append(f"Verified {payload_type} payload.")

    final_score = max(0, min(100, score))
    sources_checked = {
        "content_integrity": {"name": "Payload Integrity Inspection", "status": "OK", "available": True}
    }
    risk_info = evaluate_risk(final_score, sources_checked=sources_checked, scan_type="QR", confidence=90)

    report = {
        "url": raw,
        "source": "QR",
        "payload_type": payload_type,
        "score": final_score,
        "status": risk_info["status"],
        "level": risk_info["level"],
        "verdict": risk_info["verdict_label"],
        "verdict_title": risk_info["verdict_title"],
        "confidence": risk_info["confidence"],
        "signals": signals,
        "reasons": reasons,
        "sources_checked": sources_checked,
        "redirect_chain": {"hops_count": 0, "chain": []},
        "geo_ip": {},
        "network": {
            "hosts": [],
            "countries_in_path": [],
            "summary": f"{payload_type} -> {len(raw)} characters"
        },
        "threat_intel": {},
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    findings, passed_checks, technical = format_url_findings_and_checks(report)
    report["findings"] = findings
    report["passed_checks"] = passed_checks
    report["technical_details"] = technical
    return report


def scan_qr_payload(raw_payload: str) -> dict:
    """
    Main dispatching entry point for QR Code scanning:
    1. If URL -> runs through full URL Scanner pipeline
    2. If UPI -> runs through UPI forensic analyzer
    3. If WiFi -> runs through WiFi security analyzer
    4. Otherwise -> runs through general payload inspector
    """
    cleaned = (raw_payload or "").strip()
    payload_type = detect_qr_payload_type(cleaned)

    if payload_type == "URL":
        # Ensure scheme is present
        target_url = cleaned
        if not re.match(r"^[a-zA-Z]+://", target_url):
            target_url = "https://" + target_url

        report = scan_url(target_url)
        report["source"] = "QR"
        report["payload_type"] = "URL"
        return report

    if payload_type == "UPI":
        return analyze_upi_payload(cleaned)

    if payload_type == "WiFi":
        return analyze_wifi_payload(cleaned)

    return analyze_general_payload(cleaned, payload_type)


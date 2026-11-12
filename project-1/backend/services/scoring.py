# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
Explainable Scoring Engine
Computes transparent composite risk score (0-100), explainable signal rationale,
confidence ratings, and derives security verdicts via a single unified function.
Centralized single source of truth for URL Scanner, QR Scanner, and Email Analyzer.
"""


def verdict_from_score(score: int) -> dict:
    """
    Centralized single source of truth for deriving security verdict from risk score.
    Score ranges:
      0..29   -> Low risk / Safe
      30..69  -> Elevated risk / Suspicious
      70..100 -> High risk / Malicious
    """
    score = max(0, min(100, int(score)))
    if score >= 70:
        return {
            "status": "MALICIOUS",
            "level": "High Risk",
            "verdict": "High risk, do not open",
            "verdict_title": "Malicious",
            "color": "danger"
        }
    if score >= 30:
        return {
            "status": "SUSPICIOUS",
            "level": "Elevated Risk",
            "verdict": "Elevated risk, proceed with caution",
            "verdict_title": "Suspicious",
            "color": "warning"
        }
    return {
        "status": "SAFE",
        "level": "Low Risk",
        "verdict": "Low risk, verified safe",
        "verdict_title": "Safe",
        "color": "safe"
    }


def compute_confidence(sources_checked: dict = None, scan_type: str = "URL", default_confidence: int = 90) -> int:
    """
    Computes a forensic confidence score (0-100) based on verified data sources,
    DNS lookups, and protocol telemetry.
    """
    sources_checked = sources_checked or {}
    scan_type = str(scan_type).upper()

    if scan_type in ("URL", "LINK"):
        available_major = sum(
            1 for src in ("urlhaus", "safebrowsing", "virustotal", "openphish")
            if sources_checked.get(src, {}).get("available", False)
        )
        if available_major >= 3:
            return 96
        elif available_major == 2:
            return 82
        elif available_major == 1:
            return 65
        else:
            return 45

    elif scan_type == "QR":
        # Non-URL QR payloads (UPI, WiFi, vCard, text)
        if "payee_check" in sources_checked or "upi_protocol" in sources_checked:
            return 95
        if "wifi_security" in sources_checked:
            return 90
        return default_confidence

    elif scan_type == "EMAIL":
        # Email confidence based on authentication & DNS checks
        checks_available = 0
        if sources_checked.get("spf", {}).get("checked") or sources_checked.get("spf", {}).get("available"):
            checks_available += 1
        if sources_checked.get("dkim", {}).get("checked") or sources_checked.get("dkim", {}).get("available"):
            checks_available += 1
        if sources_checked.get("dmarc", {}).get("checked") or sources_checked.get("dmarc", {}).get("available"):
            checks_available += 1
        if sources_checked.get("dns", {}).get("available"):
            checks_available += 1

        if checks_available >= 3:
            return 95
        elif checks_available >= 2:
            return 85
        elif checks_available >= 1:
            return 72
        return 65

    return default_confidence


def evaluate_risk(
    score: int,
    sources_checked: dict = None,
    scan_type: str = "URL",
    confidence: int = None
) -> dict:
    """
    Unified Single Risk Engine for CyberScape (URL Scanner, QR Scanner, Email Analyzer).
    Derives consistent verdict (Safe / Suspicious / Malicious), score (0-100), and confidence.
    """
    final_score = max(0, min(100, int(score)))
    verdict = verdict_from_score(final_score)

    if confidence is None:
        computed_conf = compute_confidence(sources_checked, scan_type=scan_type)
    else:
        computed_conf = max(0, min(100, int(confidence)))

    return {
        "score": final_score,
        "status": verdict["status"],                 # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
        "verdict": verdict["status"],                # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
        "verdict_title": verdict["verdict_title"],   # "Safe" | "Suspicious" | "Malicious"
        "verdict_label": verdict["verdict"],         # Descriptive label
        "level": verdict["level"],                   # "Low Risk", "Elevated Risk", "High Risk"
        "confidence": computed_conf,                 # 0..100
        "color": verdict["color"]                    # "safe", "warning", "danger"
    }


def compute_scan_score(signals: list[dict], sources_checked: dict, context_flags: dict = None) -> dict:
    """
    Evaluates all signal impacts, applies threat-feed auto-fail gates,
    clamps benign scores, and computes confidence.
    """
    context_flags = context_flags or {}
    score = 0
    has_critical = False
    has_warning = False
    has_feed_hit = False

    for sig in signals:
        impact = sig.get("score_impact", 0)
        sev = (sig.get("severity") or "info").lower()
        if sev == "critical":
            has_critical = True
        elif sev == "warning":
            has_warning = True

        sig_id = sig.get("id", "")
        if sig_id in ("urlhaus_malicious", "safebrowsing_malicious", "virustotal_malicious", "openphish_match", "ssrf_blocked"):
            has_feed_hit = True

        score += impact

    # 1. Threat Feed Auto-Fail rule: minimum score 85 for direct reputation hits
    if has_feed_hit:
        score = max(85, score)

    # 2. SSRF Guard auto-fail: 100
    if context_flags.get("is_ssrf_blocked"):
        score = 100

    # 3. Punycode / Brand lookalike with no reputation hit: at least 60
    if context_flags.get("is_lookalike"):
        score = max(60, score)

    # 4. Shortener leading to young or suspicious domain: at least 50
    if context_flags.get("has_shortener") and (context_flags.get("is_young_domain") or has_warning):
        score = max(50, score)

    # 5. Pure benign URL guarantee: if no critical and no warning signals, score must be <= 10
    if not has_critical and not has_warning:
        score = max(0, min(10, score))

    # Clamp score to 0..100
    final_score = max(0, min(100, int(score)))
    risk = evaluate_risk(final_score, sources_checked=sources_checked, scan_type="URL")

    return {
        "score": final_score,
        "status": risk["status"],
        "level": risk["level"],
        "verdict": risk["verdict_label"],
        "verdict_title": risk["verdict_title"],
        "confidence": risk["confidence"],
        "has_feed_hit": has_feed_hit
    }

# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
Local Heuristics & Brand Lookalike Analyzer
Evaluates structural domain anomalies, punycode/homoglyph confusable attacks,
brand impersonation (Levenshtein distance), keyword patterns, and ML model predictions.
"""

from urllib.parse import urlparse
import ipaddress
import re

import ml_engine

TOP_BRANDS = [
    "google", "paypal", "apple", "amazon", "microsoft", "netflix", "facebook",
    "chase", "wellsfargo", "bankofamerica", "binance", "coinbase", "steam",
    "discord", "dropbox", "dhl", "usps", "instagram", "whatsapp", "linkedin",
    "twitter", "ebay", "github", "adobe", "walmart", "spotify", "citi", "yahoo"
]

RISKY_TLDS = {
    "top", "xyz", "buzz", "monster", "work", "icu", "date", "mom", "ga",
    "cf", "rest", "science", "live", "bid", "click", "tokyo", "bar",
    "cc", "cn", "pw", "tk", "gq", "ml", "cfd", "sbs"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "wallet", "bank", "confirm",
    "account", "password", "signin", "recovery", "auth", "billing", "invoice"
]

CONFUSABLE_MAP = {
    "1": "l",
    "0": "o",
    "vv": "w",
    "@": "a",
    "3": "e",
    "5": "s"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_confusables(s: str) -> str:
    res = s.lower()
    for k, v in CONFUSABLE_MAP.items():
        res = res.replace(k, v)
    return res


def check_brand_lookalike(hostname: str) -> dict:
    parts = hostname.lower().split(".")
    domain_label = parts[0] if parts else hostname
    clean_label = normalize_confusables(domain_label)

    for brand in TOP_BRANDS:
        # 1. Confusable substitution: e.g. paypa1 -> paypal, g00gle -> google
        if clean_label == brand and domain_label != brand:
            return {
                "is_lookalike": True,
                "brand": brand,
                "type": "confusable_homoglyph",
                "evidence": f"Domain uses confusable characters to impersonate brand '{brand}' ('{domain_label}')."
            }

        # 2. Check exact brand embedding in suspicious compound domain
        if brand in clean_label and clean_label != brand:
            return {
                "is_lookalike": True,
                "brand": brand,
                "type": "compound_impersonation",
                "evidence": f"Domain embeds brand target '{brand}' in suspicious label '{domain_label}'."
            }

        # 3. Check typo-squatting / edit distance (on raw or normalized label)
        raw_dist = levenshtein_distance(domain_label, brand)
        clean_dist = levenshtein_distance(clean_label, brand)
        dist = min(raw_dist, clean_dist)
        if 0 < dist <= 2 and abs(len(domain_label) - len(brand)) <= 2:
            return {
                "is_lookalike": True,
                "brand": brand,
                "type": "typosquatting",
                "evidence": f"Typosquatting lookalike targeting brand '{brand}' (edit distance: {dist})."
            }

    return {"is_lookalike": False}


def evaluate_heuristics(url: str, ml_prediction: dict = None) -> dict:
    """
    Run complete heuristics evaluation on URL and its structural features.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    signals = []

    # 1. IP-literal host
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
        signals.append({
            "id": "ip_literal_host",
            "source": "Heuristics",
            "severity": "warning",
            "score_impact": 35,
            "evidence": f"URL uses raw IP literal host '{hostname}' instead of registered domain name."
        })
    except ValueError:
        pass

    # 2. "@" delimiter in authority
    if "@" in url:
        signals.append({
            "id": "at_delimiter",
            "source": "Heuristics",
            "severity": "critical",
            "score_impact": 50,
            "evidence": "URL contains '@' credential delimiter commonly abused in phishing redirection."
        })

    # 3. Punycode / IDN Homograph check
    has_punycode = "xn--" in hostname or ".xn--" in hostname or any(ord(c) > 127 for c in hostname)
    if has_punycode:
        signals.append({
            "id": "punycode_homograph",
            "source": "Heuristics",
            "severity": "critical",
            "score_impact": 50,
            "evidence": f"Punycode/IDN internationalized homograph domain detected ('{hostname}')."
        })

    # 4. Scheme check (HTTP vs HTTPS)
    if parsed.scheme.lower() == "http":
        signals.append({
            "id": "unencrypted_http",
            "source": "Heuristics",
            "severity": "warning",
            "score_impact": 15,
            "evidence": "Unencrypted HTTP transport detected without TLS encryption."
        })

    # 4. Excessive subdomains
    subdomains = hostname.split(".")
    if len(subdomains) > 3 and not is_ip:
        signals.append({
            "id": "excessive_subdomains",
            "source": "Heuristics",
            "severity": "warning",
            "score_impact": 15,
            "evidence": f"Excessive subdomain depth ({len(subdomains)} levels) obscuring true destination."
        })

    # 5. Very long URL
    if len(url) > 120:
        signals.append({
            "id": "long_url",
            "source": "Heuristics",
            "severity": "warning",
            "score_impact": 15,
            "evidence": f"Abnormally long URL string ({len(url)} characters)."
        })

    # 6. Risky TLD
    tld = subdomains[-1] if subdomains else ""
    if tld in RISKY_TLDS:
        signals.append({
            "id": "risky_tld",
            "source": "Heuristics",
            "severity": "warning",
            "score_impact": 20,
            "evidence": f"High-risk Top-Level Domain (.{tld}) with elevated phishing prevalence."
        })

    # 7. Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        signals.append({
            "id": "non_standard_port",
            "source": "Heuristics",
            "severity": "warning",
            "score_impact": 20,
            "evidence": f"Non-standard HTTP port ({parsed.port}) in destination address."
        })

    # 8. Brand lookalike
    lookalike = check_brand_lookalike(hostname)
    if lookalike.get("is_lookalike"):
        signals.append({
            "id": "brand_lookalike",
            "source": "Heuristics",
            "severity": "critical",
            "score_impact": 60,
            "evidence": lookalike["evidence"]
        })

    # 9. Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords and (lookalike.get("is_lookalike") or is_ip or tld in RISKY_TLDS):
        signals.append({
            "id": "suspicious_keywords",
            "source": "Heuristics",
            "severity": "warning",
            "score_impact": 25,
            "evidence": f"Deceptive security/credential keywords in URL path: {', '.join(found_keywords)}."
        })

    # 10. Existing AI Machine Learning Classifier
    ml = ml_prediction or ml_engine.predict_phishing(url)
    if ml.get("label") == "Phishing":
        signals.append({
            "id": "ai_phishing_model",
            "source": "AI Model",
            "severity": "critical",
            "score_impact": 65,
            "evidence": f"AI Random Forest model flagged structural phishing characteristics ({ml.get('confidence', 85)}% confidence)."
        })
    elif ml.get("label") == "Suspicious":
        signals.append({
            "id": "ai_suspicious_model",
            "source": "AI Model",
            "severity": "warning",
            "score_impact": 35,
            "evidence": f"AI model detected anomalous domain structure ({ml.get('confidence', 60)}% confidence)."
        })
    else:
        signals.append({
            "id": "ai_clean_model",
            "source": "AI Model",
            "severity": "safe",
            "score_impact": -5,
            "evidence": f"AI Classifier: Clean structural domain profile ({ml.get('confidence', 95)}% legitimate confidence)."
        })

    return {
        "signals": signals,
        "ml": ml,
        "lookalike": lookalike,
        "is_ip": is_ip
    }


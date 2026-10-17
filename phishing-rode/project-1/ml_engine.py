"""
CyberScape ML Engine — AI-Powered Phishing Domain Detection
Extracts lexical and structural indicators from URLs and runs an ensemble Random Forest model.
"""

import math
import os
import re
from urllib.parse import urlparse
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

MODEL_FILE = os.path.join(os.path.dirname(__file__), "phishing_rf_model.joblib")

SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "tk", "ml", "ga", "cf", "gq", "work", "icu",
    "cam", "live", "bid", "club", "fit", "surf", "monster", "rest", "bar",
    "country", "stream", "gdn", "mom", "kim", "party", "racing", "date",
    "download", "accountant", "faith", "cricket", "trade", "science"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update", "security",
    "banking", "secure", "wallet", "confirm", "password", "credential",
    "authenticate", "support", "billing", "invoice", "refund", "appleid",
    "paypal", "chase", "wellsfargo", "netflix-login", "microsoft-online"
]

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "has_ip",
    "has_at_symbol",
    "subdomain_count",
    "hyphen_count",
    "is_https",
    "has_suspicious_tld",
    "suspicious_keyword_count",
    "has_double_slash_path",
    "digit_ratio",
    "shannon_entropy"
]

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for domain randomness detection."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    for char in set(text):
        p_x = text.count(char) / text_len
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)

def is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    clean_host = host.split(":")[0].strip("[]")
    # IPv4 regex
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", clean_host):
        return True
    # IPv6 check
    if ":" in clean_host:
        return True
    return False

def extract_features(url: str) -> dict:
    """Extract 12 cybersecurity phishing features from raw URL."""
    cleaned = (url or "").strip()
    parsed = urlparse(cleaned)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    url_length = len(cleaned)
    domain_length = len(hostname)
    has_ip = 1 if is_ip_address(hostname) else 0
    has_at_symbol = 1 if "@" in cleaned else 0

    # Subdomain count
    domain_parts = hostname.split(".")
    # If not an IP, subdomains are parts minus domain and TLD (typically > 2)
    if not has_ip and len(domain_parts) > 2:
        subdomain_count = len(domain_parts) - 2
    else:
        subdomain_count = 0

    hyphen_count = hostname.count("-")
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    # TLD
    tld = domain_parts[-1] if domain_parts else ""
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Suspicious keywords in domain and path
    full_target = f"{hostname}/{path}?{query}".lower()
    keyword_matches = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_target]
    suspicious_keyword_count = len(keyword_matches)

    # Double slash in path (redirect trick)
    has_double_slash_path = 1 if "//" in path else 0

    # Digit ratio in hostname
    digits = sum(c.isdigit() for c in hostname)
    digit_ratio = round(digits / max(1, len(hostname)), 3)

    # Shannon entropy of hostname
    shannon_entropy = calculate_entropy(hostname)

    # Human-readable risk factors
    risk_factors = []
    if has_ip:
        risk_factors.append("Host is a direct raw IP address rather than a registered domain")
    if has_at_symbol:
        risk_factors.append("Presence of '@' symbol which can disguise destination credentials")
    if subdomain_count >= 3:
        risk_factors.append(f"Excessive subdomain depth ({subdomain_count} subdomains detected)")
    if hyphen_count >= 2:
        risk_factors.append(f"Multiple hyphens in domain name ({hyphen_count} detected) often used in brand spoofing")
    if not is_https:
        risk_factors.append("Unencrypted HTTP protocol without TLS/SSL certificate")
    if has_suspicious_tld:
        risk_factors.append(f"Suspicious top-level domain '.{tld}' frequently linked to disposable phishing campaigns")
    if suspicious_keyword_count >= 2:
        risk_factors.append(f"Suspicious credential/security keywords detected: {', '.join(keyword_matches[:4])}")
    elif suspicious_keyword_count == 1:
        risk_factors.append(f"Security-sensitive keyword detected: {keyword_matches[0]}")
    if has_double_slash_path:
        risk_factors.append("Abnormal double slash '//' in URI path indicating potential open redirect")
    if digit_ratio > 0.3:
        risk_factors.append(f"Abnormally high ratio of numeric digits in domain name ({int(digit_ratio*100)}%)")
    if shannon_entropy > 4.2:
        risk_factors.append("High domain character entropy indicating automated DGA (Domain Generation Algorithm)")

    features_vector = [
        url_length,
        domain_length,
        has_ip,
        has_at_symbol,
        subdomain_count,
        hyphen_count,
        is_https,
        has_suspicious_tld,
        suspicious_keyword_count,
        has_double_slash_path,
        digit_ratio,
        shannon_entropy
    ]

    return {
        "features_vector": features_vector,
        "details": {
            "url_length": url_length,
            "domain_length": domain_length,
            "has_ip": bool(has_ip),
            "has_at_symbol": bool(has_at_symbol),
            "subdomain_count": subdomain_count,
            "hyphen_count": hyphen_count,
            "is_https": bool(is_https),
            "has_suspicious_tld": bool(has_suspicious_tld),
            "tld": tld,
            "suspicious_keyword_count": suspicious_keyword_count,
            "matched_keywords": keyword_matches,
            "has_double_slash_path": bool(has_double_slash_path),
            "digit_ratio": digit_ratio,
            "shannon_entropy": shannon_entropy
        },
        "risk_factors": risk_factors
    }


def _train_and_save_model():
    """Train a calibrated Random Forest Classifier on phishing and legitimate domain feature vectors."""
    # Representative URLs: legitimate (0) and phishing (1)
    dataset = [
        # Legitimate URLs
        ("https://www.google.com/search?q=cybersecurity", 0),
        ("https://github.com/torvalds/linux", 0),
        ("https://en.wikipedia.org/wiki/Phishing", 0),
        ("https://aws.amazon.com/console/", 0),
        ("https://developer.mozilla.org/en-US/docs/Web", 0),
        ("https://microsoft.com/en-us/windows", 0),
        ("https://apple.com/iphone", 0),
        ("https://netflix.com/browse", 0),
        ("https://stackoverflow.com/questions", 0),
        ("https://linkedin.com/feed", 0),
        ("https://python.org/downloads", 0),
        ("https://cloudflare.com/learning/security", 0),
        ("https://nist.gov/cyberframework", 0),
        ("https://nytimes.com/section/technology", 0),
        ("https://bbc.com/news/technology", 0),
        ("https://cnn.com/world", 0),
        ("https://chase.com/personal/banking", 0),
        ("https://bankofamerica.com", 0),
        ("https://paypal.com/signin", 0),
        ("https://zoom.us/join", 0),
        ("https://slack.com/help", 0),
        ("https://reddit.com/r/netsec", 0),
        ("https://medium.com/@infosec", 0),
        ("https://gitlab.com/explore", 0),
        ("https://bitbucket.org", 0),
        ("https://docker.com/products", 0),
        ("https://kubernetes.io/docs", 0),
        ("https://salesforce.com/login", 0),
        ("https://dropbox.com/home", 0),
        ("https://spotify.com/us", 0),

        # Phishing / Malicious URLs
        ("http://192.168.1.105/paypal/login.php", 1),
        ("http://185.220.101.4/secure/account-verification/", 1),
        ("http://update-paypal-security-account.top/login", 1),
        ("http://appleid.verify-service-account.xyz/signin", 1),
        ("http://chase-bank-verify-login-portal.work/auth", 1),
        ("http://user@suspicious-bank-login.com/secure", 1),
        ("http://secure.banking.portal.verification.alert-update.buzz/login", 1),
        ("http://netflix-billing-update-account-2024.icu/auth", 1),
        ("http://microsoft-online-office365-verify.tk/session", 1),
        ("http://wallet-connect-ledger-sync.ga/recover", 1),
        ("http://google-drive-shared-document-auth.cf/download.exe", 1),
        ("http://free-crypto-giveaway-airdrop.live/claim", 1),
        ("http://wellsfargo-online-banking-alert.cam/confirm", 1),
        ("http://amazon-prime-payment-declined.rest/update", 1),
        ("http://103.251.167.22/admin/signin", 1),
        ("http://login-facebook-security-check.tk/verify.html", 1),
        ("http://dhl-package-tracking-fee.gq/pay", 1),
        ("http://usps-address-confirm-redelivery.buzz/tracking", 1),
        ("http://steamcommunity-gift-trade.trade/tradeoffer", 1),
        ("http://metamask-seed-phrase-restore.club/auth", 1),
        ("http://bank-of-america-verify-identity-notice.monster/login", 1),
        ("http://ebay-dispute-resolution-center.download/dispute", 1),
        ("http://irs-tax-refund-direct-deposit.mom/claim", 1),
        ("http://discord-nitro-free-3months.science/claim", 1),
        ("http://binance-kyc-aml-compliance-alert.date/login", 1)
    ]

    X = []
    y = []
    for url, label in dataset:
        feat = extract_features(url)["features_vector"]
        X.append(feat)
        y.append(label)

    X = np.array(X)
    y = np.array(y)

    model = RandomForestClassifier(n_estimators=120, max_depth=6, random_state=42)
    model.fit(X, y)
    joblib.dump(model, MODEL_FILE)
    return model


_model = None

def get_model():
    """Load cached model or train new one."""
    global _model
    if _model is not None:
        return _model
    if os.path.exists(MODEL_FILE):
        try:
            _model = joblib.load(MODEL_FILE)
            return _model
        except Exception:
            pass
    _model = _train_and_save_model()
    return _model


def predict_phishing(url: str) -> dict:
    """
    Predict phishing threat using AI Random Forest model and heuristic risk factors.
    Returns:
      label: 'Legitimate' | 'Suspicious' | 'Phishing'
      confidence: float (0 - 100)
      phishing_probability: float (0.0 - 1.0)
      risk_factors: list of identified risk reasons
      extracted_features: dict of raw feature values
    """
    extraction = extract_features(url)
    model = get_model()

    features_vector = np.array([extraction["features_vector"]])
    probs = model.predict_proba(features_vector)[0]
    # class 0: Legitimate, class 1: Phishing
    phishing_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

    # Combine with deterministic high-risk flags (e.g. raw IP host or @ symbol)
    if extraction["details"]["has_ip"] or extraction["details"]["has_at_symbol"]:
        phishing_prob = max(phishing_prob, 0.92)
    if extraction["details"]["has_suspicious_tld"] and extraction["details"]["suspicious_keyword_count"] >= 1:
        phishing_prob = max(phishing_prob, 0.88)

    # Classification thresholding
    if phishing_prob >= 0.70:
        label = "Phishing"
        confidence = round(phishing_prob * 100, 1)
        risk_level = "Critical Threat"
    elif phishing_prob >= 0.40:
        label = "Suspicious"
        confidence = round(phishing_prob * 100, 1)
        risk_level = "Elevated Risk"
    else:
        label = "Legitimate"
        confidence = round((1.0 - phishing_prob) * 100, 1)
        risk_level = "Verified Low Risk"

    return {
        "label": label,
        "confidence": confidence,
        "phishing_probability": round(phishing_prob, 3),
        "risk_level": risk_level,
        "risk_factors": extraction["risk_factors"],
        "features": extraction["details"]
    }

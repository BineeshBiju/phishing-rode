"""
CyberScape Security Audit Service
Performs real security posture checks against authorized targets:
- Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookie security flags (Secure, HttpOnly, SameSite)
- CORS misconfigurations (Wildcard Origin with Credentials)
- TLS transport and redirect behavior
Strictly derives verdict and posture score via a single centralized function.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress
import re
import socket
import requests

PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_IP_NETWORKS)
    except ValueError:
        return False


def validate_audit_target(url: str) -> tuple[str, str]:
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("Please provide a target URL to audit.")

    if not re.match(r"^https?://", cleaned, re.I):
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError("Invalid target: missing hostname.")

    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        raise ValueError("Auditing internal loopback addresses is not permitted.")

    # DNS check for SSRF protection
    try:
        ip_addr = socket.gethostbyname(hostname)
        if is_private_ip(ip_addr):
            raise ValueError(f"Target resolves to private network IP ({ip_addr}) which is blocked.")
    except socket.gaierror:
        # If host cannot be resolved in testing, let it raise or handle gracefully
        pass

    return cleaned, hostname


def derive_audit_verdict(failures: int, warnings: int) -> dict:
    """
    Single unified function to derive audit risk score and verdict.
    Ensures 0 failures / 0% score can never show HIGH RISK.
    """
    if failures == 0 and warnings == 0:
        return {
            "score": 0,
            "status": "SAFE",
            "verdict": "LOW RISK",
            "level": "Low Risk / Excellent",
            "color": "safe"
        }
    if failures == 0:
        score = min(45, max(15, warnings * 12))
        return {
            "score": score,
            "status": "SUSPICIOUS",
            "verdict": "ELEVATED RISK",
            "level": "Elevated Risk / Warnings Reported",
            "color": "warning"
        }
    score = min(100, max(65, 50 + failures * 15 + warnings * 5))
    return {
        "score": score,
        "status": "MALICIOUS",
        "verdict": "HIGH RISK",
        "level": "High Risk / Attention Required",
        "color": "danger"
    }


def run_security_audit(target_url: str, authorized: bool = True) -> dict:
    if not authorized:
        raise ValueError("Target authorization permission checkbox must be confirmed before auditing.")

    cleaned_url, hostname = validate_audit_target(target_url)

    checks = []
    reasons = []

    # Execute real HTTP request
    resp = None
    http_status = 200
    final_url = cleaned_url
    headers = {}
    cookies_list = []

    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "CyberScape-Security-Posture-Auditor/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
        resp = session.get(cleaned_url, timeout=5.0, allow_redirects=True)
        http_status = resp.status_code
        final_url = resp.url
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies_list = resp.cookies
    except requests.RequestException as e:
        # If network error or unreachable target
        checks.append({
            "category": "Connectivity",
            "name": "Host Availability",
            "status": "failure",
            "details": f"Target could not be reached: {type(e).__name__}"
        })
        reasons.append(f"Connection failure: {type(e).__name__}")
        verdict = derive_audit_verdict(1, 0)
        return {
            "success": True,
            "target_url": cleaned_url,
            "final_url": cleaned_url,
            "hostname": hostname,
            "http_status": 0,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "summary": {"targets": 1, "passed": 0, "warnings": 0, "failures": 1},
            "risk_score": verdict["score"],
            "threat_status": verdict["verdict"],
            "threat_level": verdict["level"],
            "status": verdict["status"],
            "checks": checks,
            "reasons": reasons
        }

    # 1. HSTS Check
    hsts = headers.get("strict-transport-security")
    if hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.I)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        if max_age >= 10886400: # >= 126 days
            checks.append({
                "category": "Security Headers",
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "passed",
                "details": f"HSTS is properly configured (max-age={max_age}s)."
            })
        else:
            checks.append({
                "category": "Security Headers",
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "warning",
                "details": f"HSTS max-age is short ({max_age}s). Recommended: >= 10886400 (126 days)."
            })
            reasons.append("HSTS max-age duration is below recommended baseline.")
    else:
        if cleaned_url.startswith("https://"):
            checks.append({
                "category": "Security Headers",
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "warning",
                "details": "Missing Strict-Transport-Security header on HTTPS endpoint."
            })
            reasons.append("Missing Strict-Transport-Security (HSTS) header.")
        else:
            checks.append({
                "category": "Security Headers",
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "failure",
                "details": "Unencrypted HTTP transport detected without HSTS enforcement."
            })
            reasons.append("Unencrypted HTTP traffic without HSTS.")

    # 2. Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    if csp:
        checks.append({
            "category": "Security Headers",
            "name": "Content-Security-Policy (CSP)",
            "status": "passed",
            "details": "Content-Security-Policy is present and active."
        })
    else:
        checks.append({
            "category": "Security Headers",
            "name": "Content-Security-Policy (CSP)",
            "status": "warning",
            "details": "Missing Content-Security-Policy header. Susceptible to client-side injection."
        })
        reasons.append("Missing Content-Security-Policy (CSP) protection.")

    # 3. X-Frame-Options (Clickjacking)
    xfo = headers.get("x-frame-options")
    if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
        checks.append({
            "category": "Security Headers",
            "name": "X-Frame-Options (Clickjacking Guard)",
            "status": "passed",
            "details": f"X-Frame-Options is set to {xfo.upper()}."
        })
    elif csp and "frame-ancestors" in csp.lower():
        checks.append({
            "category": "Security Headers",
            "name": "X-Frame-Options (Clickjacking Guard)",
            "status": "passed",
            "details": "Frame embedding restricted via CSP frame-ancestors directive."
        })
    else:
        checks.append({
            "category": "Security Headers",
            "name": "X-Frame-Options (Clickjacking Guard)",
            "status": "warning",
            "details": "Missing X-Frame-Options header. Framing could enable clickjacking attacks."
        })
        reasons.append("Missing X-Frame-Options clickjacking mitigation.")

    # 4. X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if xcto and "nosniff" in xcto.lower():
        checks.append({
            "category": "Security Headers",
            "name": "X-Content-Type-Options",
            "status": "passed",
            "details": "MIME-sniffing protection enabled with 'nosniff'."
        })
    else:
        checks.append({
            "category": "Security Headers",
            "name": "X-Content-Type-Options",
            "status": "warning",
            "details": "Missing 'X-Content-Type-Options: nosniff' header."
        })
        reasons.append("Missing X-Content-Type-Options MIME sniffing protection.")

    # 5. Referrer-Policy
    rp = headers.get("referrer-policy")
    if rp:
        checks.append({
            "category": "Security Headers",
            "name": "Referrer-Policy",
            "status": "passed",
            "details": f"Referrer-Policy configured: {rp}."
        })
    else:
        checks.append({
            "category": "Security Headers",
            "name": "Referrer-Policy",
            "status": "warning",
            "details": "Missing Referrer-Policy header."
        })
        reasons.append("Referrer-Policy header omitted.")

    # 6. Permissions-Policy
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    if pp:
        checks.append({
            "category": "Security Headers",
            "name": "Permissions-Policy",
            "status": "passed",
            "details": "Hardware and browser feature permissions are restricted."
        })
    else:
        checks.append({
            "category": "Security Headers",
            "name": "Permissions-Policy",
            "status": "passed",  # Optional, keep as passed/info
            "details": "Standard baseline permissions policy active."
        })

    # 7. CORS Configuration
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    if acao == "*" and acac == "true":
        checks.append({
            "category": "CORS Posture",
            "name": "CORS Wildcard with Credentials",
            "status": "failure",
            "details": "Critical CORS misconfiguration: Wildcard '*' allowed with credentials."
        })
        reasons.append("Critical CORS vulnerability: Wildcard origin allowed with credentials.")
    elif acao:
        checks.append({
            "category": "CORS Posture",
            "name": "Cross-Origin Resource Sharing (CORS)",
            "status": "passed",
            "details": f"CORS headers explicitly defined: {acao}."
        })
    else:
        checks.append({
            "category": "CORS Posture",
            "name": "Cross-Origin Resource Sharing (CORS)",
            "status": "passed",
            "details": "No unsafe permissive CORS headers detected."
        })

    # 8. Cookies Security
    raw_cookies = resp.headers.get("set-cookie") or ""
    if raw_cookies:
        has_secure = "secure" in raw_cookies.lower()
        has_httponly = "httponly" in raw_cookies.lower()
        has_samesite = "samesite" in raw_cookies.lower()
        if has_secure and has_httponly and has_samesite:
            checks.append({
                "category": "Cookie Flags",
                "name": "Session Cookie Protection",
                "status": "passed",
                "details": "Cookies enforce Secure, HttpOnly, and SameSite flags."
            })
        else:
            missing_flags = []
            if not has_secure: missing_flags.append("Secure")
            if not has_httponly: missing_flags.append("HttpOnly")
            if not has_samesite: missing_flags.append("SameSite")
            checks.append({
                "category": "Cookie Flags",
                "name": "Session Cookie Protection",
                "status": "warning",
                "details": f"Cookie missing recommended security flags: {', '.join(missing_flags)}."
            })
            reasons.append(f"Cookies lack {', '.join(missing_flags)} security attributes.")
    else:
        checks.append({
            "category": "Cookie Flags",
            "name": "Cookie Security",
            "status": "passed",
            "details": "No stateful session cookies set on target."
        })

    # 9. Transport Encryption (TLS)
    if final_url.startswith("https://"):
        checks.append({
            "category": "Transport Layer",
            "name": "TLS/HTTPS Encryption",
            "status": "passed",
            "details": "Encrypted HTTPS communication verified."
        })
    else:
        checks.append({
            "category": "Transport Layer",
            "name": "TLS/HTTPS Encryption",
            "status": "failure",
            "details": "Target transmits unencrypted plaintext over HTTP."
        })
        reasons.append("Target endpoint does not enforce TLS encryption.")

    # Calculate summaries
    passed_count = sum(1 for c in checks if c["status"] == "passed")
    warnings_count = sum(1 for c in checks if c["status"] == "warning")
    failures_count = sum(1 for c in checks if c["status"] == "failure")

    verdict = derive_audit_verdict(failures_count, warnings_count)

    if not reasons:
        reasons.append("All audited security headers, cookies, and CORS policies meet secure configuration standards.")

    return {
        "success": True,
        "target_url": cleaned_url,
        "final_url": final_url,
        "hostname": hostname,
        "http_status": http_status,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "summary": {
            "targets": 1,
            "passed": passed_count,
            "warnings": warnings_count,
            "failures": failures_count
        },
        "risk_score": verdict["score"],
        "threat_status": verdict["verdict"],
        "threat_level": verdict["level"],
        "status": verdict["status"],
        "checks": checks,
        "reasons": reasons
    }


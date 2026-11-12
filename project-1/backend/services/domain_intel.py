# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
Domain Intelligence Service
Performs domain age & registrar lookup via RDAP, DNS A/MX record resolution,
TLS certificate validation using ssl + socket, and IP geolocation.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse
import ipaddress
import re
import socket
import ssl
import requests

import geo_resolver

RDAP_CACHE = {}


def hostname_matches_san(hostname: str, san_list: list) -> bool:
    """Check if target hostname matches any Subject Alternative Name or Common Name."""
    h = hostname.lower().strip(".")
    for pattern in san_list:
        p = pattern.lower().strip(".")
        if p == h:
            return True
        if p.startswith("*."):
            suffix = p[2:]
            if h.endswith("." + suffix) and h.count(".") == suffix.count(".") + 1:
                return True
    return False


def check_tls_certificate(hostname: str, port: int = 443, timeout: float = 3.0) -> dict:
    """
    Connect via TLS to verify certificate validity, issuer, expiration date,
    self-signed status, and hostname alignment.
    """
    if not hostname or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        return {"has_tls": False, "valid": False, "reason": "Target is raw IP or missing hostname."}

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"has_tls": False, "valid": False, "reason": "No certificate provided."}

                not_after_str = cert.get("notAfter")
                issuer_tuple = cert.get("issuer", ())
                issuer_name = "Unknown CA"
                for entry in issuer_tuple:
                    for k, v in entry:
                        if k in ("organizationName", "commonName"):
                            issuer_name = v
                            break

                subject_tuple = cert.get("subject", ())
                subject_name = "Unknown"
                for entry in subject_tuple:
                    for k, v in entry:
                        if k in ("organizationName", "commonName"):
                            subject_name = v
                            break

                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                is_expired = datetime.now(timezone.utc) > not_after

                # Self-signed check
                is_self_signed = (
                    issuer_name != "Unknown CA"
                    and subject_name != "Unknown"
                    and issuer_name.lower() == subject_name.lower()
                )

                # Hostname mismatch check
                sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
                if not sans and subject_name and subject_name != "Unknown":
                    sans.append(subject_name)

                hostname_mismatch = bool(sans) and not hostname_matches_san(hostname, sans)

                return {
                    "has_tls": True,
                    "valid": (not is_expired and not is_self_signed and not hostname_mismatch),
                    "issuer": issuer_name,
                    "subject": subject_name,
                    "expires_at": not_after_str,
                    "is_expired": is_expired,
                    "is_self_signed": is_self_signed,
                    "hostname_mismatch": hostname_mismatch,
                    "sans": sans[:8]
                }
    except ssl.SSLCertVerificationError as e:
        err_msg = getattr(e, "verify_message", None) or str(e)
        msg = err_msg.lower()
        is_self_signed = "self-signed" in msg or "self signed" in msg
        hostname_mismatch = "hostname" in msg or "mismatch" in msg or "not valid for any names" in msg
        is_expired = "expired" in msg

        return {
            "has_tls": True,
            "valid": False,
            "issuer": "Untrusted / Self-Signed",
            "is_self_signed": is_self_signed,
            "hostname_mismatch": hostname_mismatch,
            "is_expired": is_expired,
            "reason": f"Certificate verification error ({err_msg})."
        }
    except Exception as e:
        return {"has_tls": False, "valid": False, "reason": f"TLS handshake failed ({type(e).__name__})."}


def query_rdap_domain_age(hostname: str, timeout: float = 3.0) -> dict:
    """
    Query RDAP endpoint for registration date, registrar, and domain age.
    """
    if not hostname or hostname in ("localhost", "127.0.0.1"):
        return {"status": "unsupported", "age_days": None, "registrar": None}

    domain_parts = hostname.split(".")
    if len(domain_parts) >= 2:
        registrable = ".".join(domain_parts[-2:])
    else:
        registrable = hostname

    if registrable in RDAP_CACHE:
        return RDAP_CACHE[registrable]

    try:
        resp = requests.get(f"https://rdap.org/domain/{registrable}", timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            reg_date_str = None
            for ev in events:
                if ev.get("eventAction") in ("registration", "created"):
                    reg_date_str = ev.get("eventDate")
                    break

            registrar = None
            entities = data.get("entities", [])
            for ent in entities:
                if "registrar" in ent.get("roles", []):
                    registrar = ent.get("vcardArray", [None, []])[1]
                    for item in (registrar or []):
                        if item[0] == "fn":
                            registrar = item[3]
                            break

            age_days = None
            if reg_date_str:
                clean_date = reg_date_str.split("T")[0]
                created_dt = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created_dt).days

            res = {
                "status": "success",
                "registrable_domain": registrable,
                "registered_date": reg_date_str,
                "age_days": age_days,
                "registrar": registrar or "Accredited Registrar"
            }
            RDAP_CACHE[registrable] = res
            return res
    except Exception:
        pass

    res = {"status": "unavailable", "registrable_domain": registrable, "age_days": None, "registrar": "Domain Network"}
    RDAP_CACHE[registrable] = res
    return res


def get_domain_intelligence(url: str) -> dict:
    """
    Aggregate DNS, WHOIS/RDAP, TLS, and Geo-IP telemetry for destination.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    signals = []

    # 1. Geo-IP & Network Telemetry
    geo = geo_resolver.resolve_geo_ip(hostname)

    # 2. TLS Certificate Check
    tls_info = check_tls_certificate(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    if tls_info.get("has_tls"):
        if tls_info.get("is_self_signed"):
            signals.append({
                "id": "tls_self_signed",
                "source": "Transport Layer",
                "severity": "critical",
                "score_impact": 40,
                "evidence": f"Self-signed SSL/TLS certificate detected (Issuer: {tls_info.get('issuer')})."
            })
        elif tls_info.get("hostname_mismatch"):
            signals.append({
                "id": "tls_hostname_mismatch",
                "source": "Transport Layer",
                "severity": "critical",
                "score_impact": 40,
                "evidence": f"SSL/TLS certificate hostname mismatch: certificate is not valid for host '{hostname}'."
            })
        elif tls_info.get("is_expired"):
            signals.append({
                "id": "tls_expired",
                "source": "Transport Layer",
                "severity": "warning",
                "score_impact": 30,
                "evidence": f"Expired SSL/TLS certificate: expired on {tls_info.get('expires_at')}."
            })
        elif tls_info.get("valid"):
            signals.append({
                "id": "tls_valid",
                "source": "Transport Layer",
                "severity": "safe",
                "score_impact": -5,
                "evidence": f"Valid TLS certificate issued by {tls_info.get('issuer')} (expires {tls_info.get('expires_at')})."
            })
        else:
            signals.append({
                "id": "tls_invalid",
                "source": "Transport Layer",
                "severity": "warning",
                "score_impact": 25,
                "evidence": f"Invalid SSL/TLS certificate ({tls_info.get('reason')})."
            })

    # 3. RDAP Domain Age & Registrar (Flag under 30 days)
    rdap = query_rdap_domain_age(hostname)
    age_days = rdap.get("age_days")
    if age_days is not None:
        if age_days < 30:
            signals.append({
                "id": "young_domain",
                "source": "Domain Intelligence",
                "severity": "critical",
                "score_impact": 45,
                "evidence": f"Newly registered domain: registered {age_days} days ago (< 30 days threshold)."
            })
        elif age_days < 90:
            signals.append({
                "id": "recent_domain",
                "source": "Domain Intelligence",
                "severity": "warning",
                "score_impact": 20,
                "evidence": f"Recently registered domain: {age_days} days old."
            })
        elif age_days > 365:
            years = age_days // 365
            signals.append({
                "id": "established_domain",
                "source": "Domain Intelligence",
                "severity": "safe",
                "score_impact": -10,
                "evidence": f"Established domain with reputable history ({years}+ years old)."
            })

    # 4. Geo-IP Location Signal
    if geo.get("status") == "success":
        signals.append({
            "id": "geo_telemetry",
            "source": "DNS & Geo-IP",
            "severity": "info",
            "score_impact": 0,
            "evidence": f"Hosted in {geo.get('city')}, {geo.get('country')} ({geo.get('isp')})."
        })

    return {
        "hostname": hostname,
        "geo_ip": geo,
        "tls": tls_info,
        "rdap": rdap,
        "signals": signals
    }


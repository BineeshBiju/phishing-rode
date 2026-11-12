# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
SSRF-Safe Redirect Chain Tracer
Follows HTTP redirect chains up to 10 hops without client-side script execution or downloading bodies.
Enforces strict pre-request DNS resolution checks blocking private, loopback, link-local,
and reserved IP addresses to prevent SSRF vulnerabilities.
"""

from urllib.parse import urlparse, urljoin
import ipaddress
import socket
import requests

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "rb.gy", "v.gd", "snip.ly", "t.ly", "shorturl.at"
}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class SSRFSecurityException(Exception):
    """Raised when a target hostname or IP belongs to a restricted internal network."""
    pass


def is_url_shortener(url: str) -> bool:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    return hostname in SHORTENER_DOMAINS or hostname.startswith("tiny.") or hostname.startswith("short.")


def check_ip_ssrf_safety(ip_str: str):
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in PRIVATE_NETWORKS:
            if ip in net:
                raise SSRFSecurityException(f"Destination IP '{ip_str}' is within restricted network {net}.")
    except ValueError:
        pass


def resolve_and_verify_hostname(hostname: str) -> list[str]:
    """
    Resolve DNS for target hostname and confirm none of the resolved IPs are internal.
    """
    if not hostname:
        raise ValueError("Missing hostname for DNS verification.")

    # Check if host is raw IP
    try:
        ip_obj = ipaddress.ip_address(hostname)
        check_ip_ssrf_safety(str(ip_obj))
        return [str(ip_obj)]
    except ValueError:
        pass

    resolved_ips = []
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                check_ip_ssrf_safety(ip_str)
                resolved_ips.append(ip_str)
    except socket.gaierror:
        # Host could not be resolved; allow caller to handle connection error
        pass

    return resolved_ips


def trace_redirects(start_url: str, max_hops: int = 10, timeout_per_hop: float = 5.0) -> dict:
    """
    Safely traces HTTP redirection chain step-by-step.
    Pre-resolves DNS before every outbound request to prevent SSRF.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberScape-Security-Sandbox/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    current_url = (start_url or "").strip()
    chain = []
    visited = set()
    signals = []
    has_shortener = False
    is_cross_domain = False
    initial_host = (urlparse(start_url).hostname or "").lower()

    hop_num = 1
    while hop_num <= max_hops:
        if current_url in visited:
            chain.append({
                "step": hop_num,
                "url": current_url,
                "status_code": 310,
                "domain": (urlparse(current_url).hostname or "").lower(),
                "reason": "Circular redirect detected",
                "is_shortener": is_url_shortener(current_url),
                "redirect_to": None
            })
            signals.append({
                "id": "circular_redirect",
                "source": "Redirect Sandbox",
                "severity": "warning",
                "score_impact": 20,
                "evidence": f"Circular redirect loop detected at hop {hop_num}."
            })
            break

        visited.add(current_url)
        parsed = urlparse(current_url)
        current_host = (parsed.hostname or "").lower()

        if current_host and initial_host and current_host != initial_host:
            is_cross_domain = True

        shortener_flag = is_url_shortener(current_url)
        if shortener_flag:
            has_shortener = True

        # Pre-request SSRF security check
        try:
            resolve_and_verify_hostname(current_host)
        except SSRFSecurityException as ssrf_err:
            chain.append({
                "step": hop_num,
                "url": current_url,
                "status_code": 403,
                "domain": current_host,
                "reason": f"Blocked by SSRF Guard: {str(ssrf_err)}",
                "is_shortener": shortener_flag,
                "redirect_to": None
            })
            signals.append({
                "id": "ssrf_blocked",
                "source": "SSRF Guard",
                "severity": "critical",
                "score_impact": 100,
                "evidence": str(ssrf_err)
            })
            break

        try:
            resp = session.get(current_url, allow_redirects=False, timeout=timeout_per_hop, stream=True)
            status_code = resp.status_code
            location = resp.headers.get("Location")
            resp.close()

            step_info = {
                "step": hop_num,
                "url": current_url,
                "status_code": status_code,
                "domain": current_host,
                "is_shortener": shortener_flag,
                "redirect_to": None,
                "reason": "Terminal Destination"
            }

            if status_code in (301, 302, 303, 307, 308) and location:
                resolved_location = urljoin(current_url, location)
                step_info["redirect_to"] = resolved_location
                step_info["reason"] = f"HTTP {status_code} Redirect"
                chain.append(step_info)
                current_url = resolved_location
                hop_num += 1
            else:
                step_info["reason"] = f"HTTP {status_code} Final Destination"
                chain.append(step_info)
                break

        except requests.RequestException as e:
            chain.append({
                "step": hop_num,
                "url": current_url,
                "status_code": 0,
                "domain": current_host,
                "is_shortener": shortener_flag,
                "error": f"Connection terminated ({type(e).__name__})",
                "reason": "Unreachable Destination",
                "redirect_to": None
            })
            break

    final_url = chain[-1]["url"] if chain else start_url
    is_redirected = len(chain) > 1

    if has_shortener:
        signals.append({
            "id": "url_shortener",
            "source": "Redirect Sandbox",
            "severity": "warning",
            "score_impact": 25,
            "evidence": "URL shortening service detected in redirect pathway."
        })

    if is_cross_domain and is_redirected:
        signals.append({
            "id": "cross_domain_redirect",
            "source": "Redirect Sandbox",
            "severity": "warning",
            "score_impact": 15,
            "evidence": f"Redirect chain traverses cross-domain boundary ({initial_host} -> {urlparse(final_url).hostname})."
        })

    return {
        "initial_url": start_url,
        "final_url": final_url,
        "hops_count": len(chain),
        "is_redirected": is_redirected,
        "has_shortener": has_shortener,
        "is_cross_domain": is_cross_domain,
        "chain": chain,
        "signals": signals
    }


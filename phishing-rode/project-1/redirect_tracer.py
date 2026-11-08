"""
CyberScape Redirect Chain Tracker & Sandbox Tracer
Safely traces HTTP redirect chains without executing client-side scripts.
Detects URL shorteners, cloaking techniques, and intermediate proxy hops.
"""

from urllib.parse import urlparse, urljoin
import requests

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "rb.gy", "v.gd", "snip.ly", "t.ly", "shorturl.at"
}


def is_url_shortener(url: str) -> bool:
    """Check if the given URL domain is a known URL shortening service."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    return hostname in SHORTENER_DOMAINS or hostname.startswith("tiny.") or hostname.startswith("short.")


def trace_redirect_chain(start_url: str, max_hops: int = 8) -> dict:
    """
    Safely trace the HTTP redirection chain step-by-step.
    Does not download file contents or execute client-side JavaScript.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberScape-Security-Sandbox/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    current_url = (start_url or "").strip()
    chain = []
    visited = set()
    hop_num = 1

    while hop_num <= max_hops:
        if current_url in visited:
            chain.append({
                "step": hop_num,
                "url": current_url,
                "status_code": 310,
                "note": "Circular redirect detected",
                "is_shortener": is_url_shortener(current_url)
            })
            break

        visited.add(current_url)

        try:
            # We use stream=True so we only read the response headers, not the payload
            resp = session.get(current_url, allow_redirects=False, timeout=4, stream=True)
            status_code = resp.status_code
            location = resp.headers.get("Location")

            step_info = {
                "step": hop_num,
                "url": current_url,
                "status_code": status_code,
                "domain": urlparse(current_url).hostname or "",
                "is_shortener": is_url_shortener(current_url),
                "redirect_to": None
            }

            # 301 Moved Permanently, 302 Found, 303 See Other, 307 Temporary, 308 Permanent
            if status_code in (301, 302, 303, 307, 308) and location:
                # Handle relative redirect locations
                resolved_location = urljoin(current_url, location)
                step_info["redirect_to"] = resolved_location
                chain.append(step_info)
                current_url = resolved_location
                hop_num += 1
            else:
                step_info["redirect_to"] = None
                chain.append(step_info)
                break

        except requests.RequestException as e:
            chain.append({
                "step": hop_num,
                "url": current_url,
                "status_code": 0,
                "domain": urlparse(current_url).hostname or "",
                "is_shortener": is_url_shortener(current_url),
                "error": f"Connection terminated or host offline ({type(e).__name__})",
                "redirect_to": None
            })
            break

    final_url = chain[-1]["url"] if chain else start_url
    has_redirect = len(chain) > 1
    has_shortener = any(step.get("is_shortener") for step in chain)

    return {
        "initial_url": start_url,
        "final_url": final_url,
        "hops_count": len(chain),
        "is_redirected": has_redirect,
        "has_shortener": has_shortener,
        "chain": chain
    }

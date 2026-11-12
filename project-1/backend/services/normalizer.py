# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
URL Normalizer & Validator
Normalizes destination URLs, validates schemes, extracts hostnames in IDN/punycode form,
and detects IP-literal destinations.
"""

from urllib.parse import urlparse, urlunparse
import ipaddress
import re

MAX_URL_LENGTH = 2048
VALID_SCHEMES = {"http", "https"}
DISALLOWED_SCHEMES = {"javascript", "data", "file", "vbscript", "blob", "about"}


class InvalidURLError(ValueError):
    """Raised when a URL fails syntax, length, or scheme validation."""
    pass


def normalize_url(raw_url: str) -> dict:
    """
    Validate and normalize input URL.
    Returns structured metadata including punycode and IP-literal detection.
    """
    cleaned = (raw_url or "").strip()
    if not cleaned:
        raise InvalidURLError("URL string cannot be empty.")

    if len(cleaned) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.")

    # Check for disallowed schemes upfront
    for bad_scheme in DISALLOWED_SCHEMES:
        if cleaned.lower().startswith(f"{bad_scheme}:"):
            raise InvalidURLError(f"Disallowed URL scheme: '{bad_scheme}'. Only HTTP and HTTPS are permitted.")

    # Auto-add scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        # If looks like IPv4 or host
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()

    if scheme not in VALID_SCHEMES:
        raise InvalidURLError(f"Unsupported URL scheme: '{scheme}'. Only HTTP and HTTPS are permitted.")

    raw_netloc = parsed.netloc
    if not raw_netloc:
        raise InvalidURLError("URL is missing a valid destination hostname.")

    # Extract userinfo, host, port
    port = parsed.port
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise InvalidURLError("Unable to resolve a valid hostname from URL.")

    # Punycode / IDN conversion
    try:
        punycode_host = hostname.encode("idna").decode("ascii")
    except Exception:
        punycode_host = hostname

    has_punycode = punycode_host.startswith("xn--") or ".xn--" in punycode_host

    # IP-literal detection
    is_ip_literal = False
    ip_version = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip_literal = True
        ip_version = ip_obj.version
    except ValueError:
        is_ip_literal = False

    # Reconstruct normalized URL
    normalized = urlunparse((
        scheme,
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""  # strip fragments for scanner consistency
    ))

    return {
        "original_url": raw_url,
        "normalized_url": normalized,
        "scheme": scheme,
        "hostname": hostname,
        "punycode_host": punycode_host,
        "has_punycode": has_punycode,
        "is_ip_literal": is_ip_literal,
        "ip_version": ip_version,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query
    }


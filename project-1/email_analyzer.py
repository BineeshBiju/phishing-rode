"""
CyberScape AI Fake Email & Header Tracker
Forensic engine for detecting domain spoofing, fake senders, SPF/DKIM failures,
originating IP telemetry, brand impersonation, and phishing intent.
"""

import email
from email import policy
import ipaddress
import re
from urllib.parse import urlparse
import geo_resolver

# Known high-profile brands targeted by phishers and their legitimate domains
TARGETED_BRANDS = {
    "paypal": ["paypal.com", "paypal.me", "paypal-communication.com"],
    "google": ["google.com", "googlemail.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com"],
    "apple": ["apple.com", "icloud.com", "itunes.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
    "chase": ["chase.com", "jpmorganchase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "dhl": ["dhl.com", "dhl-express.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com", "usps.gov"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "coinbase": ["coinbase.com"]
}

# High-urgency and panic trigger phrases (NLP Heuristic Matrix)
URGENCY_PATTERNS = [
    (r"\b(?:account|access|service)\s+(?:suspended|terminated|restricted|locked|frozen|disabled)\b", 25, "Threat of account suspension or termination"),
    (r"\b(?:within|in)\s+(?:24|12|48|2|1)\s+(?:hours?|hrs?|minutes?)\b", 20, "Strict time deadline / panic induction"),
    (r"\b(?:immediate|urgent|critical)\s+(?:action|attention|verification|response)\s+(?:required|needed)\b", 20, "Urgent action demand"),
    (r"\b(?:unauthorized|suspicious|unusual)\s+(?:login|activity|access|transaction|sign-in)\b", 18, "Fabricated security alert or breach claim"),
    (r"\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|identity|password|credentials|billing|ssn|wallet|card)\b", 22, "Credential or billing verification prompt"),
    (r"\b(?:click|tap)\s+(?:here|the link|below|to verify|to confirm)\b", 15, "Direct call to action to click external link"),
    (r"\b(?:failure|fail)\s+to\s+(?:comply|verify|respond)\s+(?:will|may)\s+result\b", 20, "Coercive consequence statement"),
    (r"\b(?:security|fraud)\s+(?:alert|warning|department|team)\b", 12, "Authority figure mimicry"),
    (r"\b(?:congratulations|you(?:'ve|\s+have)\s+won|lottery|unclaimed|bonus|airdrop|reward)\b", 25, "Prize / financial lure scam pattern")
]


def defang_url(url: str) -> str:
    """Defang a URL for safe display without hyperlinking (e.g., hxxps://...)."""
    if not url:
        return ""
    defanged = re.sub(r"^https", "hxxps", url, flags=re.I)
    defanged = re.sub(r"^http", "hxxp", defanged, flags=re.I)
    defanged = defanged.replace(".", "[.]").replace("://", "[:]//")
    return defanged


def extract_ip_from_header(received_headers: list) -> str:
    """
    Extract the earliest public originating IP address from Received header lines.
    Traverses from bottom (oldest hop / client submission) to top.
    """
    ipv4_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")

    # Reverse order: oldest hop at client is typically lowest Received line
    for header in reversed(received_headers):
        ips = ipv4_pattern.findall(header)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast):
                    return ip
            except ValueError:
                continue

    return ""


def parse_email_headers(raw_header_text: str) -> dict:
    """
    Parse raw email headers and perform technical sender spoofing & authentication checks.
    """
    # Normalize line endings
    clean_text = (raw_header_text or "").replace("\r\n", "\n").strip()
    if not clean_text:
        return {"has_header": False}

    # Ensure header ends with double newline if only headers provided
    if "\n\n" not in clean_text:
        clean_text += "\n\n"

    try:
        msg = email.message_from_string(clean_text, policy=policy.default)
    except Exception:
        return {"has_header": False, "error": "Invalid email header format"}

    from_header = msg.get("From") or ""
    return_path = msg.get("Return-Path") or ""
    reply_to = msg.get("Reply-To") or ""
    subject = msg.get("Subject") or ""
    date = msg.get("Date") or ""
    received_headers = msg.get_all("Received") or []
    received_spf = msg.get("Received-SPF") or ""
    auth_results = msg.get("Authentication-Results") or ""
    dkim_sig = msg.get("DKIM-Signature") or ""

    # Extract email addresses and display names
    from_name, from_addr = email.utils.parseaddr(from_header)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    _, return_addr = email.utils.parseaddr(return_path)
    return_domain = return_addr.split("@")[-1].lower() if "@" in return_addr else ""

    _, reply_addr = email.utils.parseaddr(reply_to)
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""

    # 1. Sender Spoofing Detection
    spoofing_flags = []
    is_spoofed = False

    if from_domain and return_domain and from_domain != return_domain:
        # Check if one is a subdomain of the other
        if not (from_domain.endswith("." + return_domain) or return_domain.endswith("." + from_domain)):
            spoofing_flags.append(
                f"Domain Mismatch: 'From' domain ({from_domain}) differs from 'Return-Path' domain ({return_domain})."
            )
            is_spoofed = True

    if from_domain and reply_domain and from_domain != reply_domain:
        if not (from_domain.endswith("." + reply_domain) or reply_domain.endswith("." + from_domain)):
            spoofing_flags.append(
                f"Suspicious Reply-To: Responses route to ({reply_domain}) instead of sender ({from_domain})."
            )
            is_spoofed = True

    # Display name deception (e.g. "PayPal Service <attacker@evil.com>")
    for brand, legit_domains in TARGETED_BRANDS.items():
        if re.search(r"\b" + re.escape(brand) + r"\b", from_name, re.I):
            if from_domain and not any(from_domain.endswith(d) for d in legit_domains):
                spoofing_flags.append(
                    f"Display Name Spoofing: Display name mimics '{brand.title()}', but sender domain is '{from_domain}'."
                )
                is_spoofed = True

    # 2. SPF, DKIM, DMARC Authentication Parsing
    spf_status = "NONE"
    dkim_status = "NONE"
    dmarc_status = "NONE"

    combined_auth = f"{received_spf} {auth_results}".lower()
    if "spf=pass" in combined_auth or "pass" in received_spf.lower():
        spf_status = "PASS"
    elif "spf=fail" in combined_auth or "fail" in received_spf.lower():
        spf_status = "FAIL"
    elif "spf=softfail" in combined_auth or "softfail" in received_spf.lower():
        spf_status = "SOFTFAIL"

    if "dkim=pass" in combined_auth or (dkim_sig and "dkim=fail" not in combined_auth):
        dkim_status = "PASS"
    elif "dkim=fail" in combined_auth:
        dkim_status = "FAIL"

    if "dmarc=pass" in combined_auth:
        dmarc_status = "PASS"
    elif "dmarc=fail" in combined_auth:
        dmarc_status = "FAIL"

    # Overall Auth Verdict
    if is_spoofed or spf_status in ("FAIL", "SOFTFAIL") or dmarc_status == "FAIL":
        auth_verdict = "FAILED (Spoofed Domain)"
        auth_level = "FAIL"
    elif spf_status == "PASS" and dkim_status == "PASS":
        auth_verdict = "PASSED"
        auth_level = "PASS"
    elif spf_status == "PASS" or dkim_status == "PASS":
        auth_verdict = "PARTIAL PASS"
        auth_level = "WARN"
    else:
        auth_verdict = "UNVERIFIED (No Security Records)"
        auth_level = "UNKNOWN"

    # 3. Originating IP and Geo-Location
    originating_ip = extract_ip_from_header(received_headers)
    geo_data = geo_resolver.resolve_geo_ip(originating_ip) if originating_ip else {
        "status": "unresolved",
        "ip": "Not Detected in Header",
        "country": "Unknown Origin",
        "country_code": "UN",
        "flag": "🌐",
        "city": "Unknown",
        "region": "Unknown",
        "isp": "Local or Relayed Client",
        "coordinates": "0.0000, 0.0000"
    }

    return {
        "has_header": True,
        "from_header": from_header,
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "return_path": return_path,
        "return_domain": return_domain,
        "reply_to": reply_to,
        "reply_domain": reply_domain,
        "subject": subject,
        "date": date,
        "is_spoofed": is_spoofed,
        "spoofing_flags": spoofing_flags,
        "authentication": {
            "verdict": auth_verdict,
            "level": auth_level,
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "raw_spf": received_spf[:120] if received_spf else "",
            "raw_auth": auth_results[:120] if auth_results else ""
        },
        "originating_ip": originating_ip or "N/A",
        "geo_ip": geo_data
    }


def analyze_email_content(subject_text: str, body_text: str, sender_domain: str = "") -> dict:
    """
    Analyze email subject and body using NLP urgency patterns, brand impersonation detection,
    and hyperlink extraction.
    """
    full_text = f"{subject_text or ''}\n{body_text or ''}".strip()
    if not full_text:
        return {"has_content": False}

    # 1. Urgency & Panic Detection (NLP)
    urgency_matches = []
    urgency_score = 0

    for pattern, weight, reason in URGENCY_PATTERNS:
        match = re.search(pattern, full_text, re.IGNORECASE)
        if match:
            urgency_score += weight
            urgency_matches.append({
                "phrase": match.group(0),
                "reason": reason,
                "weight": weight
            })

    # Normalized intent scoring
    if urgency_score >= 45:
        intent_level = "HIGH"
        intent_desc = "Critical Deceptive Panic / Phishing Intent"
    elif urgency_score >= 20:
        intent_level = "MEDIUM"
        intent_desc = "Elevated Persuasion / Urgency Indicators"
    else:
        intent_level = "LOW"
        intent_desc = "Standard Informational Intent"

    # 2. Brand Impersonation Detection
    brand_impersonations = []
    for brand, legit_domains in TARGETED_BRANDS.items():
        if re.search(r"\b" + re.escape(brand) + r"\b", full_text, re.IGNORECASE):
            # If a sender domain is known and not matching the brand
            if sender_domain and not any(sender_domain.endswith(d) for d in legit_domains):
                brand_impersonations.append({
                    "brand": brand.title(),
                    "sender_domain": sender_domain,
                    "reason": f"Content mentions '{brand.title()}' but sending domain '{sender_domain}' is not an authorized property."
                })

    # 3. URL Extraction & Defanging
    # Regex to capture http/https URLs and html hrefs
    url_pattern = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
    raw_urls = list(dict.fromkeys(url_pattern.findall(full_text)))

    extracted_links = []
    for url in raw_urls[:10]:
        parsed = urlparse(url)
        clean_url = url.rstrip(".,;!?:")
        defanged = defang_url(clean_url)
        extracted_links.append({
            "original_url": clean_url,
            "defanged_url": defanged,
            "domain": parsed.hostname or "",
            "is_ip": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.hostname or ""))
        })

    return {
        "has_content": True,
        "phishing_intent": intent_level,
        "intent_description": intent_desc,
        "urgency_score": min(100, urgency_score),
        "urgency_triggers": urgency_matches,
        "brand_impersonations": brand_impersonations,
        "extracted_urls": extracted_links,
        "urls_count": len(extracted_links)
    }


def full_email_investigation(header_input: str, content_input: str) -> dict:
    """
    Combined technical header verification + NLP email text phishing analysis.
    Produces comprehensive safety score (0 - 100), risk breakdown, and verdict.
    """
    # If the user pasted an entire raw RFC 822 email message in one box
    combined_input = header_input or content_input
    if ("From:" in combined_input or "Received:" in combined_input) and ("\n\n" in combined_input) and not content_input:
        parts = combined_input.split("\n\n", 1)
        header_text = parts[0]
        body_text = parts[1] if len(parts) > 1 else ""
    else:
        header_text = header_input or ""
        body_text = content_input or ""

    # Parse headers
    header_res = parse_email_headers(header_text)
    sender_domain = header_res.get("from_domain", "") if header_res.get("has_header") else ""

    # Parse content
    content_res = analyze_email_content(header_res.get("subject", ""), body_text, sender_domain=sender_domain)

    # Calculate Composite Threat Score (0 - 100)
    score = 0
    risk_factors = []

    # 1. Header & Spoofing Penalties
    if header_res.get("has_header"):
        if header_res.get("is_spoofed"):
            score += 40
            for flag in header_res.get("spoofing_flags", []):
                risk_factors.append(flag)

        auth = header_res.get("authentication", {})
        if auth.get("level") == "FAIL":
            score += 25
            risk_factors.append(f"Email Authentication Failure: SPF/DKIM validation returned {auth.get('verdict')}")
        elif auth.get("level") == "WARN":
            score += 10
            risk_factors.append("Partial email authentication: DKIM or SPF record incomplete")

    # 2. Content & NLP Penalties
    if content_res.get("has_content"):
        if content_res.get("phishing_intent") == "HIGH":
            score += 35
            risk_factors.append(f"Psychological Panic Urgency: High frequency of coercive action triggers detected")
        elif content_res.get("phishing_intent") == "MEDIUM":
            score += 18
            risk_factors.append("Elevated urgency and action demand language identified in message text")

        for imp in content_res.get("brand_impersonations", []):
            score += 30
            risk_factors.append(imp["reason"])

        # URL risks
        ip_links = [u for u in content_res.get("extracted_urls", []) if u["is_ip"]]
        if ip_links:
            score += 30
            risk_factors.append(f"Dangerous Hyperlink: Email body contains direct IP-based links ({ip_links[0]['domain']})")

        if content_res.get("urls_count", 0) > 0 and not risk_factors:
            risk_factors.append(f"Discovered {content_res['urls_count']} embedded external hyperlinks in message")

    score = min(100, max(0, score))

    if score >= 70:
        verdict = "MALICIOUS"
        level = "High Risk Fake Email / Phishing"
    elif score >= 35:
        verdict = "SUSPICIOUS"
        level = "Elevated Risk — Potential Spoofing"
    else:
        verdict = "SAFE"
        level = "Low Risk / Authenticated Sender"
        if not risk_factors:
            risk_factors.append("Email headers align with sending server; zero coercive panic markers detected.")

    return {
        "score": score,
        "verdict": verdict,
        "level": level,
        "risk_factors": risk_factors,
        "header_analysis": header_res,
        "content_analysis": content_res,
        "summary": {
            "authentication": header_res.get("authentication", {}).get("verdict", "UNVERIFIED"),
            "originating_country": f"{header_res.get('geo_ip', {}).get('flag', '🌐')} {header_res.get('geo_ip', {}).get('country', 'Unknown')}",
            "originating_ip": header_res.get("originating_ip", "N/A"),
            "phishing_intent": content_res.get("phishing_intent", "LOW"),
            "is_spoofed": header_res.get("is_spoofed", False),
            "urls_detected": content_res.get("urls_count", 0)
        }
    }

# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
CyberScape AI Fake Email & Header Tracker
Advanced forensic engine for detecting domain spoofing, fake senders,
SPF/DKIM/DMARC failures, originating IP telemetry, brand impersonation,
and phishing intent (including CEO fraud, financial wire scams, and anchor-href deception).
"""

import email
import email.parser
import email.utils
from email import policy
import hashlib
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Union, Tuple

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from services.network_intel import geolocate
except ImportError:
    geolocate = None

import geo_resolver
from backend.services.scoring import evaluate_risk

DANGEROUS_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".iso", ".html", ".htm", ".lnk",
    ".bat", ".cmd", ".scr", ".ps1", ".hta", ".wsf", ".dll",
    ".jar", ".cpl", ".reg", ".pif", ".msc"
}

DOUBLE_EXT_PATTERN = re.compile(
    r"\.[a-zA-Z0-9]{2,5}\.(?:exe|js|vbs|iso|html|htm|lnk|bat|cmd|scr|ps1|hta|wsf|dll|jar|cpl|reg|pif|msc)$",
    re.IGNORECASE
)

# Known high-profile brands targeted by phishers and their legitimate primary domains
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
    "coinbase": ["coinbase.com"],
    "github": ["github.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"]
}

FREEMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "mail.com", "zoho.com", "proton.me", "protonmail.com"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "ru", "buzz", "icu", "work", "monster", "fit", "tk", "ml", "ga", "cf", "gq"
}

EXECUTIVE_TITLES = [
    r"\bceo\b", r"\bchief\s+executive\b", r"\bcfo\b", r"\bchief\s+financial\b",
    r"\bpresident\b", r"\bmanaging\s+director\b", r"\bvice\s+president\b",
    r"\bexecutive\s+director\b", r"\bboard\s+of\s+directors\b", r"\bchairman\b"
]

# High-urgency, financial, and panic trigger phrases (NLP Heuristic Matrix)
URGENCY_PATTERNS = [
    (r"\b(?:account|access|service)\s+(?:(?:is|has\s+been|will\s+be|was)\s+)?(?:suspended|terminated|restricted|locked|frozen|disabled)\b", 25, "Threat of account suspension or termination", "high"),
    (r"\b(?:within|in)\s+(?:24|12|48|2|1)\s+(?:hours?|hrs?|minutes?)\b", 20, "Strict time deadline / panic induction", "medium"),
    (r"\b(?:immediate|urgent|critical)\s+(?:action|attention|verification|response)\s+(?:required|needed)\b", 20, "Urgent action demand", "high"),
    (r"\b(?:unauthorized|suspicious|unusual)\s+(?:login|activity|access|transaction|sign-in)\b", 18, "Fabricated security alert or breach claim", "medium"),
    (r"\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|identity|password|credentials|billing|ssn|wallet|card)\b", 22, "Credential or billing verification prompt", "high"),
    (r"\b(?:click|tap)\s+(?:here|the link|below|to verify|to confirm)\b", 15, "Direct call to action to click external link", "medium"),
    (r"\b(?:failure|fail)\s+to\s+(?:comply|verify|respond)\s+(?:will|may)\s+result\b", 20, "Coercive consequence statement", "high"),
    (r"\b(?:security|fraud)\s+(?:alert|warning|department|team)\b", 12, "Authority figure mimicry", "low"),
    (r"\b(?:congratulations|you(?:'ve|\s+have)\s+won|lottery|unclaimed|bonus|airdrop|reward)\b", 25, "Prize / financial lure scam pattern", "high"),
    # CEO Fraud / BEC / Wire Patterns
    (r"\b(?:wire\s+transfer|wire\s+deposit|electronic\s+transfer|wire\s+payment)\b", 25, "Urgent wire transfer or financial payment solicitation", "critical"),
    (r"\b(?:confidential\s+executive|confidential\s+board|keep\s+this\s+confidential|strictly\s+confidential)\b", 20, "Pretext of executive secrecy / confidentiality", "high"),
    (r"\b(?:do\s+not\s+discuss|cannot\s+take\s+calls|cannot\s+take\s+voice|in\s+a\s+meeting|in\s+conference)\b", 20, "Channel restriction preventing out-of-band identity verification", "high"),
    (r"\b(?:before\s+3\s*pm|before\s+end\s+of\s+day|today|right\s+now|asap|at\s+your\s+desk\s+right\s+now)\b", 18, "Severe temporal urgency demanding instant execution", "high"),
    (r"\b(?:gift\s+cards?|apple\s+gift|itunes\s+card|steam\s+card|google\s+play\s+card)\b", 30, "Gift card payment demand (classic scam indicator)", "critical"),
    (r"\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?", 15, "Specific large dollar amount financial lure", "medium")
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute classic Levenshtein edit distance between two strings."""
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


def defang_url(url: str) -> str:
    """Defang a URL for safe display without hyperlinking (e.g., hxxps://...)."""
    if not url:
        return ""
    defanged = re.sub(r"^https", "hxxps", url, flags=re.I)
    defanged = re.sub(r"^http", "hxxp", defanged, flags=re.I)
    defanged = defanged.replace(".", "[.]").replace("://", "[:]//")
    return defanged


def extract_registered_domain(domain: str) -> str:
    """Extract organizational/registered domain (e.g., sub.example.co.uk -> example.co.uk or sub.example.com -> example.com)."""
    if not domain:
        return ""
    domain = domain.lower().strip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    # Handle multi-part suffixes like .co.uk, .gov.in, .ac.in
    if parts[-2] in {"co", "com", "gov", "ac", "edu", "org", "net"} and len(parts[-1]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_ip_from_header(received_headers: list) -> str:
    """
    Extract the earliest public originating IP address from Received header lines.
    Traverses from bottom (oldest hop / client submission) to top.
    Supports both IPv4 and IPv6 addresses.
    """
    ipv4_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    ipv6_pattern = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")

    for header in reversed(received_headers):
        ips = ipv4_pattern.findall(header)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_link_local):
                    return ip
            except ValueError:
                continue

        # IPv6 check
        ipv6s = ipv6_pattern.findall(header)
        for ip in ipv6s:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_link_local):
                    return ip
            except ValueError:
                continue

    return ""


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable bytes, KB, or MB."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def parse_received_hops(received_headers: list) -> List[Dict[str, Any]]:
    """
    Parse the Received header chain into a chronological hop timeline.
    Headers are listed newest-to-oldest in email, so we traverse in reverse
    order (oldest/origin to newest receiving MTA).
    Calculates time delay between hops and flags the earliest public originating IP.
    """
    hops = []
    if not received_headers:
        return hops

    ipv4_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    ipv6_pattern = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")

    origin_flagged = False
    prev_dt = None

    # Traverse in chronological order (bottom to top)
    for idx, header in enumerate(reversed(received_headers)):
        clean_hdr = str(header).replace("\n", " ").replace("\r", " ")

        # Extract 'from' and 'by' servers
        from_match = re.search(r"\bfrom\s+([^\s();]+)", clean_hdr, re.I)
        by_match = re.search(r"\bby\s+([^\s();]+)", clean_hdr, re.I)
        with_match = re.search(r"\bwith\s+([a-zA-Z0-9.\-_]+)", clean_hdr, re.I)

        from_server = from_match.group(1) if from_match else "Unknown"
        by_server = by_match.group(1) if by_match else "Unknown"
        protocol = with_match.group(1).upper() if with_match else "SMTP"

        # Extract IP address(es)
        ips = ipv4_pattern.findall(clean_hdr)
        ipv6s = ipv6_pattern.findall(clean_hdr)
        all_ips = ips + ipv6s

        public_ip = None
        selected_ip = "N/A"
        is_public = False

        for ip in all_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_link_local):
                    public_ip = ip
                    selected_ip = ip
                    is_public = True
                    break
                elif selected_ip == "N/A":
                    selected_ip = ip
            except ValueError:
                continue

        # Parse timestamp after semicolon
        dt = None
        timestamp_str = ""
        if ";" in clean_hdr:
            date_candidate = clean_hdr.rsplit(";", 1)[-1].strip()
            try:
                dt = email.utils.parsedate_to_datetime(date_candidate)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                timestamp_str = date_candidate[:30]

        # Calculate delay from previous hop
        delay_str = "0s"
        delay_seconds = 0
        if prev_dt and dt:
            try:
                sec = int((dt - prev_dt).total_seconds())
                delay_seconds = sec
                if sec < 0:
                    delay_str = "0s (clock skew)"
                elif sec < 60:
                    delay_str = f"+{sec}s"
                elif sec < 3600:
                    delay_str = f"+{sec // 60}m {sec % 60}s"
                else:
                    delay_str = f"+{sec // 3600}h {(sec % 3600) // 60}m"
            except Exception:
                pass
        if dt:
            prev_dt = dt

        # Flag origin IP: earliest hop with a valid public IP
        is_origin = False
        if not origin_flagged and is_public:
            is_origin = True
            origin_flagged = True

        # Geo-locate public IP
        geo_info = {}
        if is_public:
            if geolocate:
                try:
                    geo_info = geolocate(selected_ip)
                except Exception:
                    pass
            if not geo_info or geo_info.get("status") == "unresolved":
                try:
                    geo_info = geo_resolver.resolve_geo_ip(selected_ip)
                except Exception:
                    pass

        hops.append({
            "hop_number": idx + 1,
            "hop_index": idx,
            "from_server": from_server,
            "by_server": by_server,
            "protocol": protocol,
            "ip": selected_ip,
            "is_public": is_public,
            "is_origin": is_origin,
            "delay": delay_str,
            "delay_seconds": delay_seconds,
            "timestamp": timestamp_str,
            "geo": {
                "country": geo_info.get("country") or "Unknown",
                "country_code": geo_info.get("country_code") or "UN",
                "city": geo_info.get("city") or "Unknown",
                "isp": geo_info.get("isp") or geo_info.get("org") or "Relay Node",
                "asn": geo_info.get("asn") or "N/A"
            }
        })

    # If no public IP was flagged, flag first hop as origin
    if not origin_flagged and hops:
        hops[0]["is_origin"] = True

    return hops


def check_ip_in_spf_record(domain: str, test_ip: str, depth: int = 0) -> Dict[str, Any]:
    """
    Real DNS SPF verification using dnspython:
    Queries domain's TXT record, evaluates whether test_ip matches designated ip4/ip6 or include mechanisms.
    """
    res = {
        "authorized": False,
        "checked": False,
        "mechanism": None,
        "spf_record": None,
        "explanation": "No SPF lookup performed."
    }
    if not domain or not test_ip or test_ip in ("N/A", "Unknown", "") or not dns:
        return res

    try:
        ip_obj = ipaddress.ip_address(test_ip)
    except ValueError:
        return res

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1.5
        resolver.timeout = 1.5

        answers = resolver.resolve(domain, "TXT")
        spf_rec = None
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf_rec = txt
                break

        if not spf_rec:
            res["checked"] = True
            res["explanation"] = f"No SPF record published for domain '{domain}'."
            return res

        res["spf_record"] = spf_rec
        res["checked"] = True

        mechanisms = spf_rec.split()
        for mech in mechanisms:
            mech_lower = mech.lower()
            if mech_lower.startswith("ip4:"):
                cidr = mech[4:]
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in net:
                        res["authorized"] = True
                        res["mechanism"] = mech
                        res["explanation"] = f"Originating IP {test_ip} is explicitly authorized in '{domain}' SPF ({mech})."
                        return res
                except ValueError:
                    pass
            elif mech_lower.startswith("ip6:"):
                cidr = mech[4:]
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in net:
                        res["authorized"] = True
                        res["mechanism"] = mech
                        res["explanation"] = f"Originating IP {test_ip} is explicitly authorized in '{domain}' SPF ({mech})."
                        return res
                except ValueError:
                    pass
            elif mech_lower.startswith("include:") and depth < 2:
                inc_domain = mech[8:]
                sub_res = check_ip_in_spf_record(inc_domain, test_ip, depth + 1)
                if sub_res.get("authorized"):
                    res["authorized"] = True
                    res["mechanism"] = f"include:{inc_domain} -> {sub_res.get('mechanism')}"
                    res["explanation"] = f"Originating IP {test_ip} is authorized via include:{inc_domain} ({sub_res.get('mechanism')})."
                    return res

        # Not matched
        res["authorized"] = False
        res["explanation"] = f"Originating IP {test_ip} was NOT found in any authorized SPF mechanism for domain '{domain}'."
        return res

    except Exception as e:
        res["checked"] = False
        res["explanation"] = f"DNS SPF lookup for '{domain}' unavailable or timed out: {e}"
        return res


def check_dkim_selector_record(domain: str, selector: str) -> Dict[str, Any]:
    """
    Real DNS DKIM verification using dnspython:
    Queries TXT record on <selector>._domainkey.<domain> to verify public key existence.
    """
    res = {
        "exists": False,
        "checked": False,
        "target": f"{selector}._domainkey.{domain}" if selector and domain else None,
        "record": None,
        "explanation": "No DKIM selector query performed."
    }
    if not domain or not selector or not dns:
        return res

    target = f"{selector}._domainkey.{domain}"
    res["target"] = target

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1.5
        resolver.timeout = 1.5

        answers = resolver.resolve(target, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "p=" in txt or "v=DKIM1" in txt:
                res["exists"] = True
                res["checked"] = True
                res["record"] = txt[:80] + ("..." if len(txt) > 80 else "")
                res["explanation"] = f"DKIM selector record exists in DNS at '{target}' with valid public key."
                return res

        res["checked"] = True
        res["explanation"] = f"DNS record exists at '{target}', but no valid DKIM public key was detected."
        return res

    except Exception as e:
        res["checked"] = True
        res["exists"] = False
        res["explanation"] = f"DKIM selector DNS record not found at '{target}'."
        return res


def check_alignment(from_domain: str, return_domain: str, dkim_domain: str) -> Dict[str, Any]:
    """
    Check DMARC alignment between From header domain, Return-Path domain (SPF),
    and cryptographic DKIM d= domain.
    Supports both strict (exact match) and relaxed (same registered domain) alignment.
    """
    from_reg = extract_registered_domain(from_domain)
    return_reg = extract_registered_domain(return_domain)
    dkim_reg = extract_registered_domain(dkim_domain)

    # SPF Alignment
    spf_strict = bool(from_domain and return_domain and from_domain == return_domain)
    spf_relaxed = bool(from_reg and return_reg and from_reg == return_reg)
    spf_aligned = spf_strict or spf_relaxed

    # DKIM Alignment
    dkim_strict = bool(from_domain and dkim_domain and from_domain == dkim_domain)
    dkim_relaxed = bool(from_reg and dkim_reg and from_reg == dkim_reg)
    dkim_aligned = dkim_strict or dkim_relaxed

    overall_aligned = spf_aligned or dkim_aligned

    return {
        "spf_mode": "strict" if spf_strict else ("relaxed" if spf_relaxed else "fail"),
        "spf_alignment": "strict" if spf_strict else ("relaxed" if spf_relaxed else "fail"),
        "spf_aligned": spf_aligned,
        "dkim_mode": "strict" if dkim_strict else ("relaxed" if dkim_relaxed else "fail"),
        "dkim_alignment": "strict" if dkim_strict else ("relaxed" if dkim_relaxed else "fail"),
        "dkim_aligned": dkim_aligned,
        "overall_aligned": overall_aligned,
        "explanation": (
            "SPF and DKIM domains align with sender From header."
            if (spf_aligned and dkim_aligned)
            else (
                "Partial alignment: one protocol aligns with sender domain."
                if overall_aligned
                else "Alignment Failure: Neither SPF envelope nor DKIM signature domain aligns with From domain."
            )
        )
    }


def check_dns_auth_records(domain: str) -> Dict[str, Any]:
    """
    Perform fallback DNS lookups with short timeouts for SPF and DMARC TXT records.
    Never throws an unhandled exception if offline or DNS is unavailable.
    """
    result = {
        "spf_record": None,
        "dmarc_record": None,
        "dmarc_policy": None,
        "dns_available": False
    }
    if not domain or not dns:
        return result

    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 1.2
        resolver.timeout = 1.2

        # Check SPF on domain
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    result["spf_record"] = txt
                    result["dns_available"] = True
                    break
        except Exception:
            pass

        # Check DMARC on _dmarc.<domain>
        try:
            dmarc_host = f"_dmarc.{domain}"
            answers_dmarc = resolver.resolve(dmarc_host, "TXT")
            for rdata in answers_dmarc:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    result["dmarc_record"] = txt
                    result["dns_available"] = True
                    # Extract policy p=reject / quarantine / none
                    p_match = re.search(r"\bp=([a-z]+)", txt, re.I)
                    if p_match:
                        result["dmarc_policy"] = p_match.group(1).lower()
                    break
        except Exception:
            pass

    except Exception:
        pass

    return result


def parse_email_headers(raw_header_text: str) -> dict:
    """
    Parse raw email headers robustly using email.parser.HeaderParser.
    Performs comprehensive sender spoofing, lookalike domain, and authentication checks.
    """
    clean_text = (raw_header_text or "").replace("\r\n", "\n").strip()
    if not clean_text:
        return {"has_header": False}

    # If the user pasted an address only (e.g., "From: support@paypal.com" or just "support@paypal.com")
    if ":" not in clean_text and "@" in clean_text:
        clean_text = f"From: <{clean_text}>\n\n"
    elif "\n\n" not in clean_text:
        clean_text += "\n\n"

    try:
        parser = email.parser.HeaderParser(policy=policy.default)
        msg = parser.parsestr(clean_text)
    except Exception:
        try:
            msg = email.message_from_string(clean_text, policy=policy.default)
        except Exception:
            return {"has_header": False, "error": "Invalid email header format"}

    from_header = str(msg.get("From") or "").strip()
    return_path = str(msg.get("Return-Path") or "").strip()
    reply_to = str(msg.get("Reply-To") or "").strip()
    sender_header = str(msg.get("Sender") or "").strip()
    message_id = str(msg.get("Message-ID") or "").strip()
    subject = str(msg.get("Subject") or "").strip()
    date = str(msg.get("Date") or "").strip()
    received_headers = [str(r) for r in (msg.get_all("Received") or [])]
    received_spf = str(msg.get("Received-SPF") or "").strip()
    auth_results = str(msg.get("Authentication-Results") or "").strip()
    dkim_sig = str(msg.get("DKIM-Signature") or "").strip()

    # Extract email addresses and display names
    from_name, from_addr = email.utils.parseaddr(from_header)
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    _, return_addr = email.utils.parseaddr(return_path)
    return_domain = return_addr.split("@")[-1].lower() if "@" in return_addr else ""

    _, reply_addr = email.utils.parseaddr(reply_to)
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""

    _, sender_addr = email.utils.parseaddr(sender_header)
    sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

    msg_id_domain = ""
    if "@" in message_id:
        msg_id_domain = message_id.split("@")[-1].rstrip(">").strip().lower()

    # Extract DKIM d= domain and s= selector
    dkim_domain = ""
    dkim_selector = ""
    if dkim_sig:
        d_match = re.search(r"\bd=([a-zA-Z0-9.\-_]+)", dkim_sig)
        if d_match:
            dkim_domain = d_match.group(1).lower()
        s_match = re.search(r"\bs=([a-zA-Z0-9.\-_]+)", dkim_sig)
        if s_match:
            dkim_selector = s_match.group(1)

    # 1. Sender Spoofing & Domain Mismatch Checks
    spoofing_flags = []
    is_spoofed = False

    from_reg = extract_registered_domain(from_domain)
    return_reg = extract_registered_domain(return_domain)
    reply_reg = extract_registered_domain(reply_domain)
    sender_reg = extract_registered_domain(sender_domain)

    # Alignment verification
    alignment_data = check_alignment(from_domain, return_domain, dkim_domain)

    # From vs Return-Path
    if from_domain and return_domain:
        if from_reg != return_reg:
            spoofing_flags.append(
                f"Domain Mismatch: 'From' domain ({from_domain}) differs from 'Return-Path' envelope domain ({return_domain})."
            )
            is_spoofed = True

    # From vs Reply-To
    if from_domain and reply_domain:
        if from_reg != reply_reg:
            spoofing_flags.append(
                f"Suspicious Reply-To Routing: Replies are routed to '{reply_domain}' instead of the sending domain '{from_domain}'."
            )
            is_spoofed = True

    # From vs Sender
    if from_domain and sender_domain and from_reg != sender_reg:
        spoofing_flags.append(
            f"Sender Header Discrepancy: Declared 'Sender' ({sender_domain}) does not match 'From' ({from_domain})."
        )
        is_spoofed = True

    # From vs DKIM d=
    if from_domain and dkim_domain and from_reg != extract_registered_domain(dkim_domain):
        spoofing_flags.append(
            f"DKIM Alignment Failure: Cryptographic signature domain '{dkim_domain}' does not align with 'From' domain '{from_domain}'."
        )
        is_spoofed = True

    # 2. Display Name Spoofing & Executive Mimicry
    # Case A: Brand in Display Name
    for brand, legit_domains in TARGETED_BRANDS.items():
        if re.search(r"\b" + re.escape(brand) + r"\b", from_name, re.I):
            if from_domain and not any(from_domain.endswith(d) for d in legit_domains):
                spoofing_flags.append(
                    f"Brand Display Name Spoofing: Display name mimics '{brand.title()}', but sender domain is '{from_domain}'."
                )
                is_spoofed = True

    # Case B: Freemail with Brand Display Name
    if from_domain in FREEMAIL_PROVIDERS:
        for brand in TARGETED_BRANDS:
            if re.search(r"\b" + re.escape(brand) + r"\b", from_name, re.I):
                spoofing_flags.append(
                    f"Freemail Brand Spoofing: Display name mimics '{brand.title()}', but uses a public free-mail account ({from_domain})."
                )
                is_spoofed = True
                break

    # Case C: Executive Title in Display Name on Freemail
    for title_pat in EXECUTIVE_TITLES:
        if re.search(title_pat, from_name, re.I):
            if from_domain in FREEMAIL_PROVIDERS:
                spoofing_flags.append(
                    f"Executive Impersonation: Display name contains authority title '{from_name}', but uses a free public email provider ({from_domain})."
                )
                is_spoofed = True
                break

    # 3. Lookalike / Typosquatting / Suspicious Domains
    lookalike_warnings = []
    if from_domain:
        sld = from_domain.split(".")[0] if "." in from_domain else from_domain
        # Check against target brands
        for brand in TARGETED_BRANDS:
            if sld != brand and len(sld) >= 4 and len(brand) >= 4:
                dist = levenshtein_distance(sld, brand)
                if dist in (1, 2) or (sld.replace("0", "o").replace("1", "l").replace("rn", "m") == brand):
                    lookalike_warnings.append(
                        f"Lookalike / Typosquatting Domain: '{from_domain}' closely mimics legitimate brand '{brand.title()}' (edit distance {dist})."
                    )
                    is_spoofed = True

        # Punycode check
        if "xn--" in from_domain:
            lookalike_warnings.append(f"Punycode Homograph Domain: Sender domain '{from_domain}' uses internationalized character encoding.")
            is_spoofed = True

        # Suspicious TLD check
        tld = from_domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS and any(b in from_domain for b in ["pay", "bank", "secure", "notice", "alert", "verify"]):
            lookalike_warnings.append(f"High-Risk TLD Association: Domain uses suspicious generic extension '.{tld}'.")

        # Excessive subdomains
        if from_domain.count(".") >= 4:
            lookalike_warnings.append(f"Excessive Subdomain Obfuscation: Sender domain contains {from_domain.count('.')} subdomain levels.")

    spoofing_flags.extend(lookalike_warnings)

    # 4. Authentication Parsing (SPF, DKIM, DMARC)
    spf_status = "none"
    spf_explanation = "No SPF verification header present."
    dkim_status = "none"
    dkim_explanation = "No DKIM signature verification header present."
    dmarc_status = "none"
    dmarc_explanation = "No DMARC policy validation header present."

    combined_auth = f"{received_spf} {auth_results}".lower()

    # SPF Parsing
    if "spf=pass" in combined_auth or "pass" in received_spf.lower():
        spf_status = "pass"
        spf_explanation = "Designated sending server is explicitly authorized by the sender's DNS SPF record."
    elif "spf=fail" in combined_auth or "fail" in received_spf.lower():
        spf_status = "fail"
        spf_explanation = "Sending IP is NOT authorized to send mail on behalf of the domain (Hard Fail)."
    elif "spf=softfail" in combined_auth or "softfail" in received_spf.lower():
        spf_status = "softfail"
        spf_explanation = "Sending server not recognized by domain SPF, tagged with weak non-blocking policy (~all)."
    elif "spf=neutral" in combined_auth:
        spf_status = "neutral"
        spf_explanation = "Domain SPF record explicitly evaluated to neutral (?all)."

    # DKIM Parsing
    if "dkim=pass" in combined_auth:
        dkim_status = "pass"
        dkim_explanation = f"Cryptographic signature verified successfully by receiving mail server (domain: {dkim_domain or from_domain})."
    elif "dkim=fail" in combined_auth:
        dkim_status = "fail"
        dkim_explanation = "Cryptographic signature validation failed; message body or headers may have been altered in transit."
    elif dkim_sig:
        dkim_status = "pass"
        dkim_explanation = f"DKIM-Signature present with selector for domain '{dkim_domain or from_domain}'."

    # DMARC Parsing
    if "dmarc=pass" in combined_auth:
        dmarc_status = "pass"
        dmarc_explanation = "Message passed DMARC alignment and underlying SPF/DKIM verification."
    elif "dmarc=fail" in combined_auth:
        dmarc_status = "fail"
        dmarc_explanation = "Message failed DMARC alignment requirements for the claimed From domain."

    # DNS fallback if headers are completely absent
    if (spf_status == "none" or dmarc_status == "none") and from_domain:
        dns_res = check_dns_auth_records(from_domain)
        if dns_res.get("dns_available"):
            if spf_status == "none" and dns_res.get("spf_record"):
                spf_explanation = f"Domain publishes SPF record in DNS: {dns_res['spf_record'][:60]}... (not evaluated in headers)"
            if dmarc_status == "none" and dns_res.get("dmarc_record"):
                dmarc_policy = dns_res.get("dmarc_policy") or "none"
                dmarc_explanation = f"Domain publishes DMARC record in DNS (policy: p={dmarc_policy})."

    # Overall Auth Level
    if spf_status == "fail" or dkim_status == "fail" or dmarc_status == "fail" or is_spoofed:
        auth_level = "FAIL"
        auth_verdict = "FAILED (Authentication or Alignment Failure)"
    elif spf_status == "pass" and dkim_status == "pass":
        auth_level = "PASS"
        auth_verdict = "PASSED (SPF & DKIM Verified)"
    elif spf_status == "pass" or dkim_status == "pass":
        auth_level = "WARN"
        auth_verdict = "PARTIAL PASS"
    else:
        auth_level = "UNKNOWN"
        auth_verdict = "UNVERIFIED (No Authentication Headers)"

    # 5. Received Chain Hop Timeline & Originating IP
    hop_timeline = parse_received_hops(received_headers)
    originating_ip = extract_ip_from_header(received_headers)
    if not originating_ip and hop_timeline:
        for h in hop_timeline:
            if h.get("is_origin") and h.get("is_public"):
                originating_ip = h.get("ip")
                break
        if not originating_ip and hop_timeline:
            originating_ip = hop_timeline[0].get("ip")

    # Real DNS SPF match check with dnspython
    spf_dns_info = check_ip_in_spf_record(from_domain, originating_ip)
    if spf_dns_info.get("checked") and spf_dns_info.get("spf_record"):
        if spf_dns_info.get("authorized"):
            if spf_status in ("none", "neutral"):
                spf_status = "pass"
                spf_explanation = f"DNS SPF validation confirmed: {spf_dns_info.get('explanation')}"
        elif originating_ip and originating_ip not in ("N/A", "Unknown", ""):
            if spf_status == "none":
                spf_status = "softfail"
                spf_explanation = spf_dns_info.get("explanation")

    # Real DNS DKIM selector check with dnspython
    dkim_dns_info = check_dkim_selector_record(dkim_domain or from_domain, dkim_selector)
    if dkim_dns_info.get("checked") and dkim_dns_info.get("exists"):
        if dkim_status == "none":
            dkim_status = "pass"
            dkim_explanation = f"DKIM selector record verified in DNS ({dkim_dns_info.get('target')})."

    geo_data = {}
    if originating_ip and originating_ip != "N/A":
        if geolocate:
            try:
                raw_geo = geolocate(originating_ip)
                geo_data = {
                    "status": raw_geo.get("status", "success"),
                    "ip": originating_ip,
                    "hostname": raw_geo.get("ptr") or originating_ip,
                    "country": raw_geo.get("country") or "Unknown Origin",
                    "country_code": raw_geo.get("country_code") or "UN",
                    "flag": raw_geo.get("country_code") or "UN",
                    "city": raw_geo.get("city") or "Unknown",
                    "region": raw_geo.get("region") or "Unknown",
                    "isp": raw_geo.get("isp") or raw_geo.get("org") or "Relayed Transmission Node",
                    "org": raw_geo.get("org") or "Relayed Transmission Node",
                    "asn": raw_geo.get("asn") or "N/A",
                    "coordinates": f"{raw_geo.get('lat', 0.0):.4f}, {raw_geo.get('lon', 0.0):.4f}",
                    "latitude": raw_geo.get("lat"),
                    "longitude": raw_geo.get("lon")
                }
            except Exception:
                pass

        if not geo_data or geo_data.get("status") == "unresolved":
            geo_data = geo_resolver.resolve_geo_ip(originating_ip)

    if not geo_data:
        geo_data = {
            "status": "unresolved",
            "ip": originating_ip or "Not Detected in Header",
            "country": "Unknown Origin",
            "country_code": "UN",
            "flag": "UN",
            "city": "Unknown",
            "region": "Unknown",
            "isp": "Local or Relayed Client",
            "org": "Relay Node",
            "asn": "N/A",
            "coordinates": "0.0000, 0.0000"
        }

    # Geolocation mismatch detection
    geo_mismatch = False
    if originating_ip and geo_data.get("country_code") not in {"US", "UN", "IN", "GB", "CA"}:
        if any(b in from_domain for b in ["paypal", "chase", "bankofamerica", "wellsfargo", "apple", "microsoft"]):
            geo_mismatch = True
            spoofing_flags.append(
                f"Geographic Relay Anomaly: Mail for '{from_domain}' submitted from unexpected foreign jurisdiction ({geo_data.get('country')} [{geo_data.get('country_code')}])."
            )

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
        "sender_header": sender_header,
        "sender_domain": sender_domain,
        "message_id": message_id,
        "subject": subject,
        "date": date,
        "is_spoofed": is_spoofed,
        "geo_mismatch": geo_mismatch,
        "spoofing_flags": spoofing_flags,
        "hop_timeline": hop_timeline,
        "alignment": alignment_data,
        "spf_dns": spf_dns_info,
        "dkim_dns": dkim_dns_info,
        "authentication": {
            "verdict": auth_verdict,
            "level": auth_level,
            "spf": spf_status.upper(),
            "dkim": dkim_status.upper(),
            "dmarc": dmarc_status.upper(),
            "spf_details": spf_explanation,
            "dkim_details": dkim_explanation,
            "dmarc_details": dmarc_explanation,
            "raw_spf": received_spf[:120] if received_spf else "",
            "raw_auth": auth_results[:120] if auth_results else ""
        },
        "originating_ip": originating_ip or "N/A",
        "geo_ip": geo_data
    }


def analyze_email_content(subject_text: str, body_text: str, sender_domain: str = "") -> dict:
    """
    Analyze email subject and body using NLP urgency patterns, CEO fraud detection,
    hyperlink extraction (with anchor text vs href mismatch detection), and attachment checks.
    """
    full_text = f"{subject_text or ''}\n{body_text or ''}".strip()
    if not full_text:
        return {"has_content": False}

    # Check for HTML content vs plain text
    is_html = bool(re.search(r"<(?:html|body|p|div|a\s|br|table)", full_text, re.I))

    # 1. Hyperlink Extraction & Href Mismatch Detection
    extracted_links = []
    href_mismatches = []

    # HTML <a> tag analysis
    if is_html:
        a_tags = re.findall(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', full_text, re.I | re.S)
        for href, anchor in a_tags:
            clean_href = href.strip()
            clean_anchor = re.sub(r"<[^>]+>", "", anchor).strip()
            parsed_href = urlparse(clean_href)
            href_domain = parsed_href.hostname or ""
            is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", href_domain))

            mismatch = False
            # If anchor text looks like a URL or domain
            if re.search(r"https?://|[a-zA-Z0-9.\-_]+\.(?:com|org|net|xyz|edu|gov)", clean_anchor):
                anchor_match = re.search(r"(?:https?://)?([a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,})", clean_anchor)
                if anchor_match:
                    claimed_anchor_domain = anchor_match.group(1).lower()
                    if href_domain and extract_registered_domain(claimed_anchor_domain) != extract_registered_domain(href_domain):
                        mismatch = True
                        href_mismatches.append({
                            "claimed": claimed_anchor_domain,
                            "actual_destination": clean_href,
                            "reason": f"Deceptive Hyperlink: Displayed link text claims '{claimed_anchor_domain}' but href leads to '{href_domain}'."
                        })

            extracted_links.append({
                "original_url": clean_href,
                "defanged_url": defang_url(clean_href),
                "domain": href_domain,
                "anchor_text": clean_anchor[:60] if clean_anchor else "",
                "is_ip": is_ip,
                "href_mismatch": mismatch,
                "anchor_mismatch": mismatch,
                "is_shortener": href_domain in {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}
            })

    # Plain text URL extraction (for remaining links or non-HTML)
    url_pattern = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
    raw_urls = url_pattern.findall(full_text)
    seen_urls = {u["original_url"] for u in extracted_links}

    for url in raw_urls:
        clean_url = url.rstrip(".,;!?:")
        if clean_url in seen_urls:
            continue
        seen_urls.add(clean_url)
        parsed = urlparse(clean_url)
        domain = parsed.hostname or ""
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
        extracted_links.append({
            "original_url": clean_url,
            "defanged_url": defang_url(clean_url),
            "domain": domain,
            "anchor_text": clean_url[:60],
            "is_ip": is_ip,
            "href_mismatch": False,
            "anchor_mismatch": False,
            "is_shortener": domain in {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}
        })

    # Run extracted URLs through URL Scanner threat pipeline (up to 6 links)
    try:
        from backend.services.orchestrator import scan_url
    except ImportError:
        scan_url = None

    for link in extracted_links[:6]:
        link_url = link["original_url"]
        if scan_url and link_url.startswith(("http://", "https://")):
            try:
                u_res = scan_url(link_url)
                st = u_res.get("status", "SAFE")
                link["threat_status"] = st
                link["threat_score"] = u_res.get("score", 0)
                link["threat_signals"] = u_res.get("reasons", [])
                link["is_malicious"] = (st == "MALICIOUS")
            except Exception:
                link["threat_status"] = "SAFE"
                link["threat_score"] = 0
                link["threat_signals"] = []
                link["is_malicious"] = False
        else:
            link["threat_status"] = "SAFE"
            link["threat_score"] = 0
            link["threat_signals"] = []
            link["is_malicious"] = False

    # Strip HTML tags to get pure prose for NLP pattern matching
    clean_prose = re.sub(r"<[^>]+>", " ", full_text)
    clean_prose = re.sub(r"\s+", " ", clean_prose).strip()

    # 2. Urgency, Panic & BEC NLP Triggers
    urgency_matches = []
    urgency_score = 0

    for pattern, weight, reason, sev in URGENCY_PATTERNS:
        matches = re.findall(pattern, clean_prose, re.IGNORECASE)
        if matches:
            urgency_score += weight * len(matches)
            # Add unique match
            urgency_matches.append({
                "phrase": matches[0] if isinstance(matches[0], str) else matches[0][0],
                "reason": reason,
                "weight": weight,
                "severity": sev
            })

    # CEO Fraud / BEC Specific Pattern Detection
    has_ceo_title = bool(re.search(r"\b(?:ceo|chief\s+executive|cfo|president|executive\s+board)\b", clean_prose, re.I))
    has_wire = bool(re.search(r"\b(?:wire\s+deposit|wire\s+transfer|send\s+payment|process\s+this\s+payment|wire\s+authorization)\b", clean_prose, re.I))
    has_secrecy = bool(re.search(r"\b(?:confidential|do\s+not\s+discuss|keep\s+this\s+private|between\s+us)\b", clean_prose, re.I))
    has_no_calls = bool(re.search(r"\b(?:cannot\s+take\s+calls|cannot\s+take\s+voice|cannot\s+talk|in\s+a\s+meeting)\b", clean_prose, re.I))

    ceo_fraud_detected = (has_ceo_title and has_wire) or (has_wire and has_secrecy and has_no_calls)

    # Generic greeting check (classic mass-phishing signature)
    has_generic_greeting = bool(re.search(r"\b(?:dear\s+customer|dear\s+user|dear\s+client|dear\s+account\s+holder|dear\s+member)\b", clean_prose, re.I))

    # Suspicious attachment names / double extensions
    suspicious_attachments = []
    att_matches = re.findall(r"\b[a-zA-Z0-9_\-]+\.(?:exe|scr|vbs|js|html|shtml|iso|bat|cmd|ps1)\b", clean_prose, re.I)
    double_ext_matches = re.findall(r"\b[a-zA-Z0-9_\-]+\.(?:pdf|doc|docx|xlsx|png|jpg)\.(?:exe|scr|vbs|js|html)\b", clean_prose, re.I)
    for att in (att_matches + double_ext_matches):
        suspicious_attachments.append(att)

    # Brand Impersonation in Content vs Sending Domain
    brand_impersonations = []
    for brand, legit_domains in TARGETED_BRANDS.items():
        if re.search(r"\b" + re.escape(brand) + r"\b", clean_prose, re.IGNORECASE):
            if sender_domain and not any(sender_domain.endswith(d) for d in legit_domains):
                brand_impersonations.append({
                    "brand": brand.title(),
                    "sender_domain": sender_domain,
                    "reason": f"Content mentions '{brand.title()}' but sending domain '{sender_domain}' is not an authorized property."
                })

    # Normalized Intent Level
    if ceo_fraud_detected or urgency_score >= 45:
        intent_level = "HIGH"
        intent_desc = "Critical Deceptive Urgency / Phishing Intent Detected"
    elif urgency_score >= 18 or has_generic_greeting:
        intent_level = "MEDIUM"
        intent_desc = "Elevated Persuasion / Urgency Indicators Identified"
    else:
        intent_level = "LOW"
        intent_desc = "Standard Informational Intent"

    return {
        "has_content": True,
        "phishing_intent": intent_level,
        "intent_description": intent_desc,
        "urgency_score": min(100, urgency_score),
        "urgency_triggers": urgency_matches,
        "ceo_fraud_detected": ceo_fraud_detected,
        "has_generic_greeting": has_generic_greeting,
        "suspicious_attachments": suspicious_attachments,
        "brand_impersonations": brand_impersonations,
        "href_mismatches": href_mismatches,
        "extracted_urls": extracted_links[:10],
        "urls_count": len(extracted_links)
    }


def parse_raw_email_message(raw_input: Union[str, bytes]) -> dict:
    """
    Parse a raw RFC 822 email message or .eml file.
    Extracts headers, subject, body (plain text & HTML), and attachments.
    Never executes attachment files; computes SHA256, verifies extensions and double extensions.
    """
    if isinstance(raw_input, bytes):
        try:
            msg = email.message_from_bytes(raw_input, policy=policy.default)
        except Exception:
            msg = email.message_from_string(raw_input.decode("utf-8", errors="ignore"), policy=policy.default)
    else:
        msg = email.message_from_string(raw_input, policy=policy.default)

    header_lines = []
    try:
        for k, v in msg.raw_items():
            header_lines.append(f"{k}: {v}")
    except Exception:
        for k in msg.keys():
            for v in msg.get_all(k, []):
                header_lines.append(f"{k}: {v}")
    header_text = "\n".join(header_lines)

    subject = str(msg.get("Subject") or "").strip()
    body_plain = ""
    body_html = ""
    attachments = []

    for part in msg.walk():
        fn = part.get_filename()
        cd = str(part.get("Content-Disposition") or "")
        ct = part.get_content_type()

        # Check if part is an attachment
        if fn or "attachment" in cd.lower():
            clean_fn = fn or "unnamed_attachment"
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            sha256_hash = hashlib.sha256(payload).hexdigest()
            size_bytes = len(payload)

            lower_fn = clean_fn.lower()
            is_dangerous = False
            for ext in DANGEROUS_EXTENSIONS:
                if lower_fn.endswith(ext):
                    is_dangerous = True
                    break

            is_double_ext = bool(DOUBLE_EXT_PATTERN.search(lower_fn))
            if is_double_ext:
                is_dangerous = True

            threat_flags = []
            if is_double_ext:
                threat_flags.append("DOUBLE EXTENSION")
            if is_dangerous:
                threat_flags.append("DANGEROUS EXTENSION")

            attachments.append({
                "filename": clean_fn,
                "content_type": ct,
                "size_bytes": size_bytes,
                "size_formatted": format_file_size(size_bytes),
                "sha256": sha256_hash,
                "is_dangerous": is_dangerous,
                "is_double_ext": is_double_ext,
                "threat_flags": threat_flags
            })
        elif ct == "text/plain" and not body_plain:
            try:
                body_plain = part.get_content()
            except Exception:
                pass
        elif ct == "text/html" and not body_html:
            try:
                body_html = part.get_content()
            except Exception:
                pass

    chosen_body = body_plain or body_html or ""
    if body_html and ("<a " in body_html.lower() or "<a\n" in body_html.lower()):
        chosen_body = body_html

    return {
        "header_text": header_text,
        "subject": subject,
        "body_text": chosen_body,
        "body_plain": body_plain,
        "body_html": body_html,
        "attachments": attachments
    }


def full_email_investigation(
    header_input: str,
    content_input: str,
    attachments_input: Optional[List[Dict[str, Any]]] = None
) -> dict:
    """
    Combined technical header verification + NLP email text phishing analysis.
    Produces comprehensive safety score (0 - 100), structured findings, and verdict.
    """
    combined_input = header_input or content_input
    attachments = list(attachments_input or [])

    # If full RFC 822 MIME message is pasted (e.g. into header or body) and attachments not yet extracted
    if not attachments and ("boundary=" in combined_input.lower() or "content-type: multipart" in combined_input.lower()):
        try:
            parsed_raw = parse_raw_email_message(combined_input)
            if parsed_raw.get("attachments"):
                attachments = parsed_raw.get("attachments", [])
            if not content_input and parsed_raw.get("body_text"):
                content_input = parsed_raw.get("body_text", "")
            if not header_input and parsed_raw.get("header_text"):
                header_input = parsed_raw.get("header_text", "")
        except Exception:
            pass
    elif ("From:" in combined_input or "Received:" in combined_input) and ("\n\n" in combined_input) and not content_input:
        parts = combined_input.split("\n\n", 1)
        header_text = parts[0]
        body_text = parts[1] if len(parts) > 1 else ""
    else:
        header_text = header_input or ""
        body_text = content_input or ""

    if not locals().get("header_text"):
        header_text = header_input or ""
    if not locals().get("body_text"):
        body_text = content_input or ""

    # Parse headers
    header_res = parse_email_headers(header_text)
    sender_domain = header_res.get("from_domain", "") if header_res.get("has_header") else ""

    # Parse content
    content_res = analyze_email_content(header_res.get("subject", ""), body_text, sender_domain=sender_domain)

    # Build Structured Findings & Composite Scoring
    score = 0
    findings = []
    risk_factors = []
    recommendations = []

    # 1. SENDER & SPOOFING FINDINGS
    if header_res.get("has_header"):
        if header_res.get("is_spoofed"):
            score += 35
            for flag in header_res.get("spoofing_flags", []):
                risk_factors.append(flag)
                findings.append({
                    "category": "Sender Spoofing",
                    "severity": "critical" if "Mismatch" in flag or "Impersonation" in flag else "high",
                    "title": "Sender Identity Discrepancy",
                    "explanation": flag,
                    "evidence": f"From: {header_res.get('from_addr')} | Return-Path: {header_res.get('return_path')}",
                    "recommendation": "Block or quarantine messages from this unauthorized sender; verify domain ownership."
                })

        auth = header_res.get("authentication", {})
        if auth.get("level") == "FAIL":
            score += 25
            desc = f"SPF/DKIM/DMARC authentication failed: SPF={auth.get('spf')}, DKIM={auth.get('dkim')}, DMARC={auth.get('dmarc')}."
            risk_factors.append(desc)
            findings.append({
                "category": "Authentication",
                "severity": "high",
                "title": "Email Authentication Validation Failure",
                "explanation": desc,
                "evidence": auth.get("raw_auth") or auth.get("raw_spf") or "Headers evaluated to FAIL",
                "recommendation": "Reject or flag mail failing SPF/DKIM/DMARC; enforce strict DMARC p=quarantine or p=reject."
            })
        elif auth.get("level") == "WARN":
            score += 10
            findings.append({
                "category": "Authentication",
                "severity": "medium",
                "title": "Partial Authentication Coverage",
                "explanation": "Only one authentication protocol verified. DKIM or SPF alignment incomplete.",
                "evidence": f"SPF: {auth.get('spf')} | DKIM: {auth.get('dkim')}",
                "recommendation": "Ensure both SPF and DKIM signing are configured for all outbound MTAs."
            })
        elif auth.get("level") == "PASS":
            findings.append({
                "category": "Authentication",
                "severity": "safe",
                "title": "Cryptographic Authentication Passed",
                "explanation": "Both SPF and DKIM signatures validly align with sending domain.",
                "evidence": f"SPF: {auth.get('spf')} | DKIM: {auth.get('dkim')} | DMARC: {auth.get('dmarc')}",
                "recommendation": "Cryptographic sender identity verified; maintain standard email security hygiene."
            })

        if header_res.get("geo_mismatch"):
            score += 20
            findings.append({
                "category": "Originating IP",
                "severity": "high",
                "title": "Geographic Origin Anomaly",
                "explanation": f"Claimed corporate brand originated from foreign network node ({header_res.get('geo_ip', {}).get('country')}).",
                "evidence": f"IP: {header_res.get('originating_ip')} ({header_res.get('geo_ip', {}).get('isp')})",
                "recommendation": "Review relay routing headers; inspect IP ASN origin before trusting claimed identity."
            })

    # 2. CONTENT & NLP FINDINGS
    if content_res.get("has_content"):
        if content_res.get("ceo_fraud_detected"):
            score += 45
            desc = "Executive Fraud / BEC Pattern: Urgency, executive authority, secrecy demand, and wire transfer payment solicitation detected."
            risk_factors.append(desc)
            findings.append({
                "category": "Executive Fraud",
                "severity": "critical",
                "title": "Business Email Compromise (CEO Fraud)",
                "explanation": desc,
                "evidence": "Wire transfer requested under executive pretext with out-of-band communication blockage",
                "recommendation": "Do not process payments or wire transfers; verify directly via a trusted executive phone number."
            })

        if content_res.get("phishing_intent") == "HIGH" and not content_res.get("ceo_fraud_detected"):
            score += 30
            desc = "Critical Deceptive Urgency: High frequency of account panic, threat, and credential harvesting patterns."
            risk_factors.append(desc)
            findings.append({
                "category": "Phishing Intent",
                "severity": "high",
                "title": "High Panic / Phishing Urgency",
                "explanation": desc,
                "evidence": f"Urgency Index: {content_res.get('urgency_score')}/100",
                "recommendation": "Do not rush into clicking links or verifying credentials; visit official portals directly."
            })
        elif content_res.get("phishing_intent") == "MEDIUM":
            score += 15
            findings.append({
                "category": "Phishing Intent",
                "severity": "medium",
                "title": "Moderate Action Demand",
                "explanation": "Message contains elevated urgency language prompting swift recipient compliance.",
                "evidence": f"Urgency Index: {content_res.get('urgency_score')}/100",
                "recommendation": "Verify the sender and confirm the authenticity of any requested actions before complying."
            })

        for imp in content_res.get("brand_impersonations", []):
            score += 25
            risk_factors.append(imp["reason"])
            findings.append({
                "category": "Phishing Intent",
                "severity": "high",
                "title": f"Targeted Brand Impersonation: {imp['brand']}",
                "explanation": imp["reason"],
                "evidence": f"Sender domain: '{imp['sender_domain']}'",
                "recommendation": f"Navigate directly to {imp['brand']}'s official website; do not log in from unsolicited emails."
            })

        for hm in content_res.get("href_mismatches", []):
            score += 35
            risk_factors.append(hm["reason"])
            findings.append({
                "category": "Hyperlinks",
                "severity": "critical",
                "title": "Deceptive Anchor Text vs Destination Href Mismatch",
                "explanation": hm["reason"],
                "evidence": f"Target: {hm['actual_destination']}",
                "recommendation": "Do not click deceptive links whose text conceals a different target address."
            })

        # URL risks
        ip_links = [u for u in content_res.get("extracted_urls", []) if u["is_ip"]]
        if ip_links:
            score += 30
            risk_desc = f"Direct IP Hyperlink: Email body contains direct IP-based links ({ip_links[0]['domain']})."
            risk_factors.append(risk_desc)
            findings.append({
                "category": "Hyperlinks",
                "severity": "critical",
                "title": "Raw IP Address Destination",
                "explanation": risk_desc,
                "evidence": ip_links[0]["original_url"],
                "recommendation": "Avoid direct IP destinations; legitimate corporate portals use secure domain names."
            })

        shorteners = [u for u in content_res.get("extracted_urls", []) if u["is_shortener"]]
        if shorteners:
            score += 15
            findings.append({
                "category": "Hyperlinks",
                "severity": "medium",
                "title": "URL Shortener Detected",
                "explanation": f"Link uses shortening service ({shorteners[0]['domain']}) to cloak destination endpoint.",
                "evidence": shorteners[0]["original_url"],
                "recommendation": "Expand shortened links using a preview tool before visiting the destination."
            })

        if content_res.get("has_generic_greeting") and score > 20:
            findings.append({
                "category": "Phishing Intent",
                "severity": "low",
                "title": "Generic Impersonal Greeting",
                "explanation": "Email opens with generic salutation (e.g., 'Dear customer') rather than customized name.",
                "evidence": "Dear customer / account holder",
                "recommendation": "Treat mass impersonal messages with caution when they request sensitive action."
            })

        for att in content_res.get("suspicious_attachments", []):
            score += 35
            findings.append({
                "category": "Content Findings",
                "severity": "critical",
                "title": "Dangerous Executable Attachment Referenced",
                "explanation": f"Message references high-risk executable or double-extension payload ({att}).",
                "evidence": att,
                "recommendation": "Do not open or execute attachments with executable or obscured double extensions."
            })

        # URL Scanner malicious link check
        malicious_links = [u for u in content_res.get("extracted_urls", []) if u.get("is_malicious")]
        if malicious_links:
            score += 40
            for mlink in malicious_links:
                reasons_text = ", ".join(mlink.get("threat_signals", ["Known malicious threat signature"]))
                finding_text = f"Malicious Link Detected: Destination '{mlink['defanged_url']}' was verified malicious by URL threat intelligence ({reasons_text})."
                risk_factors.append(finding_text)
                findings.append({
                    "category": "Hyperlinks",
                    "severity": "critical",
                    "title": f"Confirmed Malicious Hyperlink ({mlink.get('domain') or 'Target'})",
                    "explanation": finding_text,
                    "evidence": f"URL: {mlink['original_url']} | Status: MALICIOUS",
                    "recommendation": "Do NOT click or open this link; destination is associated with malware delivery or credential harvesting."
                })

    # Attachment Analysis (from MIME / .eml attachments)
    has_dangerous_attachment = False
    for att in attachments:
        fn = att.get("filename", "unnamed")
        sha = att.get("sha256", "N/A")
        sz = att.get("size_formatted", "")
        if att.get("is_dangerous"):
            has_dangerous_attachment = True
            is_dbl = att.get("is_double_ext")
            score += 70 if is_dbl else 45
            reason = (
                f"Disguised Double-Extension Payload: '{fn}' uses deceptive dual extensions to conceal executable code."
                if is_dbl else
                f"Dangerous Executable Attachment: '{fn}' contains executable binary or script payload."
            )
            risk_factors.append(reason)
            findings.append({
                "category": "Attachments",
                "severity": "critical",
                "title": f"Dangerous Attachment: {fn}",
                "explanation": reason,
                "evidence": f"Filename: {fn} | Size: {sz} | SHA256: {sha}",
                "recommendation": "Do not open, click, or execute this attachment. Quarantine or delete immediately."
            })

    if attachments and not has_dangerous_attachment:
        findings.append({
            "category": "Attachments",
            "severity": "safe",
            "title": f"Attachments Validated ({len(attachments)} file{'s' if len(attachments) != 1 else ''})",
            "explanation": "All attachments have non-executable extensions without double extensions.",
            "evidence": ", ".join(f"{a.get('filename')} ({a.get('size_formatted')})" for a in attachments),
            "recommendation": "Standard operational security applies: scan all files with endpoint antivirus before use."
        })

    # Legitimate safe fallback finding
    if score == 0 and not findings:
        findings.append({
            "category": "Authentication",
            "severity": "safe",
            "title": "Authentic Sender Infrastructure",
            "explanation": "Email headers align with legitimate sending servers and pass cryptographic checks.",
            "evidence": header_res.get("from_addr") or "Legitimate verified sender",
            "recommendation": "Sender identity is authenticated; adhere to standard operational security practices."
        })

    # Sort findings by severity: critical -> high -> medium -> low -> safe
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "safe": 4}
    findings.sort(key=lambda x: sev_rank.get(x.get("severity", "low"), 5))

    # Cap score and derive unified risk assessment with confidence
    sources_checked = {
        "spf": {"checked": bool(header_res.get("spf_dns")), "available": bool(header_res.get("spf_dns", {}).get("checked"))},
        "dkim": {"checked": bool(header_res.get("dkim_dns")), "available": bool(header_res.get("dkim_dns", {}).get("checked"))},
        "dmarc": {"checked": bool(header_res.get("dns_available")), "available": bool(header_res.get("dns_available"))},
        "dns": {"available": bool(header_res.get("dns_available"))}
    }
    risk_info = evaluate_risk(score, sources_checked=sources_checked, scan_type="EMAIL")
    score = risk_info["score"]
    verdict = risk_info["status"]
    level = risk_info["level"]
    confidence = risk_info["confidence"]

    if verdict == "MALICIOUS":
        recommendations = [
            "Do NOT click any links, open attachments, or reply to this sender.",
            "Report this email directly to your security operations or email administrator.",
            "Verify any urgent financial or account requests via a trusted out-of-band channel (e.g., direct phone call)."
        ]
    elif verdict == "SUSPICIOUS":
        recommendations = [
            "Exercise caution: verify the sender's identity through official independent channels.",
            "Inspect any embedded URLs before clicking; check that domains strictly match official company addresses.",
            "Ensure multi-factor authentication (MFA) is active on your accounts."
        ]
    else:
        recommendations = [
            "Email passes cryptographic authentication checks and exhibits normal characteristics.",
            "Standard security hygiene applies: always verify unexpected requests for sensitive data."
        ]
        if not risk_factors:
            risk_factors.append("Email headers align with sending server; zero coercive panic markers detected.")

    sender_check = {
        "from_name": header_res.get("from_name", ""),
        "from_addr": header_res.get("from_addr", ""),
        "from_domain": header_res.get("from_domain", ""),
        "return_path": header_res.get("return_path", ""),
        "return_domain": header_res.get("return_domain", ""),
        "reply_to": header_res.get("reply_to", ""),
        "reply_domain": header_res.get("reply_domain", ""),
        "is_spoofed": header_res.get("is_spoofed", False),
        "spoofing_flags": header_res.get("spoofing_flags", [])
    }

    auth_results = {
        "spf": {
            "status": header_res.get("authentication", {}).get("spf", "NONE"),
            "explanation": header_res.get("authentication", {}).get("spf_details", "No SPF record evaluated."),
            "dns_match": header_res.get("spf_dns", {}).get("authorized", False),
            "spf_record": header_res.get("spf_dns", {}).get("spf_record")
        },
        "dkim": {
            "status": header_res.get("authentication", {}).get("dkim", "NONE"),
            "explanation": header_res.get("authentication", {}).get("dkim_details", "No DKIM signature evaluated."),
            "dns_key_found": header_res.get("dkim_dns", {}).get("exists", False),
            "target": header_res.get("dkim_dns", {}).get("target")
        },
        "dmarc": {
            "status": header_res.get("authentication", {}).get("dmarc", "NONE"),
            "explanation": header_res.get("authentication", {}).get("dmarc_details", "No DMARC policy evaluated.")
        },
        "alignment": header_res.get("alignment", {})
    }

    origin_ip = {
        "ip": header_res.get("originating_ip", "N/A"),
        "country": header_res.get("geo_ip", {}).get("country", "Unknown Origin"),
        "country_code": header_res.get("geo_ip", {}).get("country_code", "UN"),
        "city": header_res.get("geo_ip", {}).get("city", "Unknown"),
        "isp": header_res.get("geo_ip", {}).get("isp", "Unknown ISP"),
        "asn": header_res.get("geo_ip", {}).get("asn", "N/A"),
        "hop_count": len(header_res.get("hop_timeline", []))
    }

    return {
        "has_header": bool(header_text and header_text.strip()),
        "has_content": bool(body_text and body_text.strip()),
        "score": score,
        "verdict": verdict,
        "status": verdict,
        "verdict_title": risk_info["verdict_title"],
        "level": level,
        "confidence": confidence,
        "risk_factors": risk_factors,
        "findings": findings,
        "sender_check": sender_check,
        "auth_results": auth_results,
        "alignment": header_res.get("alignment", {}),
        "origin_ip": origin_ip,
        "hop_timeline": header_res.get("hop_timeline", []),
        "attachments": attachments,
        "attachment_count": len(attachments),
        "content_findings": content_res,
        "links": content_res.get("extracted_urls", []),
        "recommendations": recommendations,
        "header_analysis": header_res,
        "content_analysis": content_res,
        "summary": {
            "authentication": header_res.get("authentication", {}).get("verdict", "UNVERIFIED"),
            "originating_country": f"{header_res.get('geo_ip', {}).get('flag', '')} {header_res.get('geo_ip', {}).get('country', 'Unknown')}",
            "originating_ip": header_res.get("originating_ip", "N/A"),
            "phishing_intent": content_res.get("phishing_intent", "LOW"),
            "is_spoofed": header_res.get("is_spoofed", False),
            "urls_detected": content_res.get("urls_count", 0),
            "attachments_count": len(attachments),
            "hops_count": len(header_res.get("hop_timeline", []))
        }
    }


def analyze_eml_file_or_bytes(file_bytes_or_str: Union[bytes, str], filename: str = "") -> dict:
    """
    Complete analysis pipeline for uploaded .eml files or raw RFC 822 email byte buffers.
    Parses headers, message body, extracts attachments, runs full forensic investigation.
    """
    parsed = parse_raw_email_message(file_bytes_or_str)
    res = full_email_investigation(
        header_input=parsed.get("header_text", ""),
        content_input=parsed.get("body_text", ""),
        attachments_input=parsed.get("attachments", [])
    )
    if filename:
        res["filename"] = filename
    return res



def analyze_eml_file_or_bytes(file_bytes_or_str: Union[bytes, str], filename: str = "") -> dict:
    """
    Complete analysis pipeline for uploaded .eml files or raw RFC 822 email byte buffers.
    Parses headers, message body, extracts attachments, runs full forensic investigation.
    """
    parsed = parse_raw_email_message(file_bytes_or_str)
    res = full_email_investigation(
        header_input=parsed.get("header_text", ""),
        content_input=parsed.get("body_text", ""),
        attachments_input=parsed.get("attachments", [])
    )
    if filename:
        res["filename"] = filename
    return res

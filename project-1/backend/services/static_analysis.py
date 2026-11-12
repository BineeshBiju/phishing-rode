# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
CyberScape Static Page Threat Analyzer
Performs lightweight, isolated static HTML analysis without JavaScript execution.
Inspects:
1. Password input fields (<input type="password">)
2. Form actions submitting credentials or data to external/cross-domain targets
3. Hidden or zero-dimension iframes used for stealth drive-by redirection
4. Obfuscated JavaScript patterns (eval, unescape, fromCharCode, packed scripts, hex byte arrays)
5. Brand name in <title> that mismatches the actual host domain
"""

from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
import ipaddress
import re
import socket
import requests

from backend.services.redirects import resolve_and_verify_hostname, SSRFSecurityException

TOP_BRANDS = [
    "paypal", "google", "apple", "amazon", "microsoft", "netflix", "facebook",
    "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica", "citi",
    "binance", "coinbase", "steam", "discord", "dropbox", "dhl", "usps",
    "fedex", "twitter", "linkedin", "adobe", "github", "ebay", "walmart"
]


class StaticHTMLParser(HTMLParser):
    def __init__(self, page_host: str):
        super().__init__()
        self.page_host = (page_host or "").lower()
        self.in_title = False
        self.in_script = False
        self.title_text = ""
        self.scripts = []
        self.has_password_field = False
        self.forms = []
        self.hidden_iframes = []
        self.inputs = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "title":
            self.in_title = True
        elif tag == "script":
            self.in_script = True
        elif tag == "input":
            input_type = attrs_dict.get("type", "text").lower()
            input_name = attrs_dict.get("name", "").lower()
            input_id = attrs_dict.get("id", "").lower()
            self.inputs.append({"type": input_type, "name": input_name, "id": input_id})
            if input_type == "password" or "password" in input_name or "passwd" in input_name or "pwd" in input_name:
                self.has_password_field = True
        elif tag == "form":
            action = attrs_dict.get("action", "").strip()
            method = attrs_dict.get("method", "GET").upper()
            self.forms.append({"action": action, "method": method})
        elif tag == "iframe":
            style = attrs_dict.get("style", "").lower().replace(" ", "")
            width = attrs_dict.get("width", "").strip()
            height = attrs_dict.get("height", "").strip()
            hidden_attr = "hidden" in attrs_dict
            src = attrs_dict.get("src", "")

            is_hidden = (
                hidden_attr
                or "display:none" in style
                or "visibility:hidden" in style
                or width in ("0", "0px", "1", "1px")
                or height in ("0", "0px", "1", "1px")
                or "opacity:0" in style
            )
            if is_hidden:
                self.hidden_iframes.append({"src": src, "style": style, "width": width, "height": height})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_title:
            self.title_text += data
        elif self.in_script:
            self.scripts.append(data)


def detect_obfuscated_js(scripts: list[str]) -> list[dict]:
    """
    Search for common malware / phishing obfuscation heuristics in script bodies.
    """
    findings = []
    combined_js = "\n".join(scripts)

    # 1. Dean Edwards packer / eval(function(p,a,c,k,e,d)
    if re.search(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)", combined_js):
        findings.append({
            "type": "packed_code",
            "pattern": "Dean Edwards Packer / eval(p,a,c,k,e,d)",
            "details": "Automated code packer detected hiding script logic."
        })

    # 2. eval(unescape(...)) or document.write(unescape(...))
    if re.search(r"(eval|document\.write)\s*\(\s*unescape\s*\(", combined_js, re.IGNORECASE):
        findings.append({
            "type": "eval_unescape",
            "pattern": "eval/document.write with unescape()",
            "details": "Obfuscated payload evaluated at runtime via unescape()."
        })

    # 3. Excessive consecutive hex escape sequences (e.g. \x61\x62\x63\x64\x65...)
    hex_matches = re.findall(r"(?:\\x[0-9a-fA-F]{2}){5,}", combined_js)
    if hex_matches:
        findings.append({
            "type": "hex_encoding",
            "pattern": f"Hex-encoded byte strings ({len(hex_matches)} occurrences)",
            "details": f"Obfuscated hex-encoded byte arrays found in page script."
        })

    # 4. Long String.fromCharCode sequences
    from_char_code = re.findall(r"String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}\d+\s*\)", combined_js)
    if from_char_code:
        findings.append({
            "type": "char_code_obfuscation",
            "pattern": f"String.fromCharCode decoding ({len(from_char_code)} calls)",
            "details": "String reconstruction via fromCharCode concealing text/URLs."
        })

    return findings


def analyze_static_html(html_content: str, current_url: str) -> dict:
    """
    Parse HTML content and identify security anomalies.
    """
    parsed_url = urlparse(current_url)
    page_host = (parsed_url.hostname or "").lower()

    parser = StaticHTMLParser(page_host)
    try:
        parser.feed(html_content[:1048576])  # limit to 1MB of content
    except Exception:
        pass

    signals = []
    findings_summary = []

    # 1. Password input field check
    if parser.has_password_field:
        findings_summary.append("Password input field detected.")
        is_unencrypted = parsed_url.scheme.lower() == "http"
        signals.append({
            "id": "html_password_field",
            "source": "Static Page Analysis",
            "severity": "critical" if is_unencrypted else "warning",
            "score_impact": 40 if is_unencrypted else 20,
            "evidence": "Password entry form detected" + (" over insecure unencrypted HTTP." if is_unencrypted else " on target page.")
        })

    # 2. Form actions pointing to cross-domain destinations
    cross_domain_forms = []
    for form in parser.forms:
        action = form.get("action") or ""
        if action.startswith(("http://", "https://")):
            form_host = (urlparse(action).hostname or "").lower()
            if form_host and page_host and form_host != page_host:
                # Exclude subdomains of same root if legitimate
                p_parts = page_host.split(".")
                f_parts = form_host.split(".")
                p_root = ".".join(p_parts[-2:]) if len(p_parts) >= 2 else page_host
                f_root = ".".join(f_parts[-2:]) if len(f_parts) >= 2 else form_host

                if p_root != f_root:
                    cross_domain_forms.append({"action": action, "target_host": form_host})

    if cross_domain_forms:
        target_hosts = list({f["target_host"] for f in cross_domain_forms})
        findings_summary.append(f"Cross-domain form action: submits data to {', '.join(target_hosts)}.")
        signals.append({
            "id": "cross_domain_form",
            "source": "Static Page Analysis",
            "severity": "critical",
            "score_impact": 50,
            "evidence": f"Form action targets external cross-domain server ({', '.join(target_hosts)} != {page_host})."
        })

    # 3. Hidden or zero-dimension iframes
    if parser.hidden_iframes:
        findings_summary.append(f"Hidden iframe detected ({len(parser.hidden_iframes)} hidden frames).")
        signals.append({
            "id": "hidden_iframe",
            "source": "Static Page Analysis",
            "severity": "high",
            "score_impact": 35,
            "evidence": f"Stealth hidden or zero-dimension <iframe> element detected ({len(parser.hidden_iframes)} instances)."
        })

    # 4. Obfuscated JavaScript patterns
    js_obfuscation = detect_obfuscated_js(parser.scripts)
    if js_obfuscation:
        patterns = [j["pattern"] for j in js_obfuscation]
        findings_summary.append(f"Obfuscated JavaScript: {'; '.join(patterns)}.")
        signals.append({
            "id": "obfuscated_js",
            "source": "Static Page Analysis",
            "severity": "critical",
            "score_impact": 45,
            "evidence": f"Obfuscated client-side JavaScript detected: {', '.join(patterns)}."
        })

    # 5. Brand name in title mismatching actual host domain
    title_clean = parser.title_text.strip()
    title_lower = title_clean.lower()
    impersonated_brand = None

    if title_clean and page_host:
        for brand in TOP_BRANDS:
            # Check if brand is mentioned in title as a standalone word
            if re.search(r"\b" + re.escape(brand) + r"\b", title_lower):
                # Verify if actual page host belongs to this brand
                if brand not in page_host:
                    impersonated_brand = brand
                    break

    if impersonated_brand:
        findings_summary.append(f"Brand impersonation in title: title references '{impersonated_brand.title()}' but domain is '{page_host}'.")
        signals.append({
            "id": "title_brand_mismatch",
            "source": "Static Page Analysis",
            "severity": "critical",
            "score_impact": 60,
            "evidence": f"Page title ('{title_clean[:60]}...') references brand '{impersonated_brand.title()}' but destination domain '{page_host}' is unaffiliated."
        })

    return {
        "status": "analyzed",
        "title": title_clean[:120] if title_clean else "Untitled Page",
        "has_password_field": parser.has_password_field,
        "cross_domain_forms": cross_domain_forms,
        "hidden_iframes_count": len(parser.hidden_iframes),
        "js_obfuscation": js_obfuscation,
        "impersonated_brand": impersonated_brand,
        "findings_summary": findings_summary,
        "signals": signals
    }


def fetch_and_analyze_page(target_url: str, timeout: float = 4.0) -> dict:
    """
    Safely fetch HTML with SSRF pre-check and run static analysis.
    Never executes JavaScript.
    """
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()

    # Pre-flight SSRF check
    try:
        resolve_and_verify_hostname(hostname)
    except SSRFSecurityException as ssrf_err:
        return {
            "status": "ssrf_blocked",
            "title": "",
            "has_password_field": False,
            "cross_domain_forms": [],
            "hidden_iframes_count": 0,
            "js_obfuscation": [],
            "impersonated_brand": None,
            "findings_summary": [f"Page fetch blocked by SSRF Guard: {str(ssrf_err)}"],
            "signals": []
        }
    except Exception:
        pass

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberScape-Security-Scanner/2.0",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"
        }
        resp = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=False, stream=True)
        content_type = (resp.headers.get("Content-Type") or "").lower()

        # Only analyze HTML
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            resp.close()
            return {
                "status": "skipped_non_html",
                "title": "",
                "has_password_field": False,
                "cross_domain_forms": [],
                "hidden_iframes_count": 0,
                "js_obfuscation": [],
                "impersonated_brand": None,
                "findings_summary": [],
                "signals": []
            }

        # Read at most 1 MB
        content = resp.raw.read(1048576, decode_content=True)
        resp.close()
        html_text = content.decode("utf-8", errors="ignore")
        return analyze_html_text(html_text, target_url)
    except Exception as err:
        return {
            "status": "unavailable",
            "title": "",
            "has_password_field": False,
            "cross_domain_forms": [],
            "hidden_iframes_count": 0,
            "js_obfuscation": [],
            "impersonated_brand": None,
            "findings_summary": [f"Static analysis skipped ({type(err).__name__})."],
            "signals": []
        }


def analyze_html_text(html_text: str, target_url: str) -> dict:
    """Entry point for evaluating static HTML string directly."""
    return analyze_static_html(html_text, target_url)


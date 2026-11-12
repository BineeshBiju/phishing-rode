"""
Unit and Integration Tests for CyberScape AI Fake Email & Header Tracker
Tests:
- Header parsing and sender spoofing detection (Levenshtein, homoglyphs, alignment)
- SPF, DKIM, and DMARC authentication validation and DNS lookups
- Originating IP extraction and geo-telemetry (bottom-up Received traversal)
- NLP urgency and panic scam analysis
- Brand impersonation and CEO executive BEC fraud detection
- Anchor text vs href mismatch detection in HTML bodies
- Defanged URL extraction
- Edge cases: missing headers, malformed headers, body-only, header-only
- PDF forensic report generation endpoint
- History persistence for email scans
"""

import pytest
from app import app, scan_history
import email_analyzer


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        yield client


def test_parse_spoofed_email_header():
    raw_header = (
        'From: "PayPal Support" <service@fake-account-update.xyz>\n'
        'Return-Path: <bounce@malicious-node.ru>\n'
        'Received: from mail.malicious-node.ru ([185.220.101.5])\n'
        'Received-SPF: fail\n'
        'Authentication-Results: mx.google.com; dkim=fail; dmarc=fail\n'
        'Subject: Account Suspended'
    )
    res = email_analyzer.parse_email_headers(raw_header)
    assert res["has_header"] is True
    assert res["is_spoofed"] is True
    assert res["from_domain"] == "fake-account-update.xyz"
    assert res["return_domain"] == "malicious-node.ru"
    assert res["originating_ip"] == "185.220.101.5"
    assert res["authentication"]["spf"] == "FAIL"
    assert "FAILED" in res["authentication"]["verdict"]


def test_originating_ip_extraction():
    received = [
        "from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mx.google.com",
        "from [192.168.1.10] (client.isp.com [185.220.101.99]) by relay.net"
    ]
    ip = email_analyzer.extract_ip_from_header(received)
    assert ip == "185.220.101.99"


def test_nlp_urgency_and_brand_impersonation():
    content = (
        "Dear customer, your PayPal account will be suspended within 24 hours. "
        "Immediate verification required. Click here to confirm: http://192.168.1.1/login"
    )
    res = email_analyzer.analyze_email_content(
        subject_text="Urgent Security Alert",
        body_text=content,
        sender_domain="suspicious-domain.xyz"
    )
    assert res["has_content"] is True
    assert res["phishing_intent"] == "HIGH"
    assert len(res["urgency_triggers"]) >= 2
    assert any(imp["brand"] == "Paypal" for imp in res["brand_impersonations"])
    assert len(res["extracted_urls"]) == 1
    assert "hxxp" in res["extracted_urls"][0]["defanged_url"]


def test_spoofed_paypal_verdict():
    """Verify Spoofed PayPal email scores as MALICIOUS (Phishing) with high risk score >= 75."""
    header = (
        'From: "PayPal Security" <service@paypal-security-alert.top>\n'
        'Return-Path: <bounce@offshore-mailer.ru>\n'
        'Received: from mailer.offshore-mailer.ru ([185.220.101.5]) by mx.recipient.com\n'
        'Received-SPF: fail (domain of paypal.com does not designate 185.220.101.5 as permitted sender)\n'
        'Authentication-Results: mx.google.com; dkim=fail; dmarc=fail\n'
        'Subject: Urgent: Your PayPal account has been restricted'
    )
    body = (
        "Dear PayPal Customer,\n\n"
        "We detected unauthorized access to your account from an unknown IP address. "
        "Your account has been suspended within 24 hours unless immediate verification is performed.\n\n"
        "Please click the verification link below to confirm your password and identity:\n"
        "http://185.220.101.5/paypal/login\n\n"
        "Failure to comply will result in permanent account termination.\n"
        "PayPal Security Department"
    )
    res = email_analyzer.full_email_investigation(header, body)
    assert res["verdict"] == "MALICIOUS"
    assert res["score"] >= 75
    assert res["auth_results"]["spf"]["status"] == "FAIL"
    assert any("paypal" in str(f).lower() for f in res["findings"])


def test_ceo_urgent_fraud_verdict():
    """Verify CEO urgent scam scores as MALICIOUS with high confidence executive BEC detection."""
    header = (
        'From: "Jane Smith (CEO)" <jane.smith.corp.ceo@gmail.com>\n'
        'Reply-To: <ceo-private-finance@offshore-holdings.ch>\n'
        'Subject: URGENT: Wire Transfer Required Before 3PM - Strictly Confidential'
    )
    body = (
        "Hi,\n\n"
        "I am currently in an all-day executive board meeting and cannot take voice calls. "
        "We have an urgent confidential acquisition closing today. "
        "Please process an immediate wire transfer of $42,500 to our escrow attorney.\n\n"
        "Keep this strictly confidential and do not discuss with anyone in the office until announced.\n\n"
        "Reply directly to this email with confirmation.\n\n"
        "Jane Smith\nChief Executive Officer"
    )
    res = email_analyzer.full_email_investigation(header, body)
    assert res["verdict"] == "MALICIOUS"
    assert res["score"] >= 70
    assert any(f.get("category") == "Executive Fraud" for f in res["findings"])


def test_legitimate_email_verdict():
    """Verify Legitimate email scores as SAFE with low risk score <= 20 and passing auth."""
    header = (
        'From: "GitHub" <notifications@github.com>\n'
        'Return-Path: <noreply@github.com>\n'
        'Received: from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mx.google.com\n'
        'Received-SPF: pass (google.com: domain of noreply@github.com designates 209.85.128.41 as permitted sender)\n'
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2014;\n'
        'Authentication-Results: mx.google.com; dkim=pass header.i=@github.com; spf=pass; dmarc=pass\n'
        'Subject: [GitHub] A new release v2.4.0 is available'
    )
    body = (
        "Hello Developer,\n\n"
        "A new release v2.4.0 is now available for your repository. "
        "You can view the release notes and changelog here: https://github.com/example/repo/releases\n\n"
        "Best regards,\n"
        "The GitHub Team"
    )
    res = email_analyzer.full_email_investigation(header, body)
    assert res["verdict"] == "SAFE"
    assert res["score"] <= 20
    assert res["auth_results"]["spf"]["status"] == "PASS"
    assert res["auth_results"]["dkim"]["status"] == "PASS"
    assert res["auth_results"]["dmarc"]["status"] == "PASS"


def test_missing_headers_graceful():
    """Verify email analyzer handles headers with missing authentication or partial fields."""
    header = "From: friend@example.com\nSubject: Coffee tomorrow?"
    body = "Hey, are we still on for coffee at 10am tomorrow?"
    res = email_analyzer.full_email_investigation(header, body)
    assert res["verdict"] in {"SAFE", "SUSPICIOUS"}
    assert res["sender_check"]["from_domain"] == "example.com"
    assert res["auth_results"]["spf"]["status"] in {"MISSING", "NEUTRAL", "PASS", "NONE"}


def test_malformed_headers():
    """Verify corrupted, non-RFC 822 header input does not crash the parser."""
    corrupted_header = ":::;;;### NOT A VALID RFC HEADER [[[\n\tRandom junk bytes\x00\x01\n=== 404 ==="
    body = "Just some text."
    res = email_analyzer.full_email_investigation(corrupted_header, body)
    assert isinstance(res, dict)
    assert "verdict" in res
    assert "score" in res
    assert isinstance(res["findings"], list)


def test_body_only_analysis():
    """Verify input with empty header and only body text analyzes correctly."""
    body = (
        "URGENT: Your bank account will be suspended within 12 hours. "
        "Verify your credentials immediately at http://192.168.1.1/login"
    )
    res = email_analyzer.full_email_investigation("", body)
    assert res["has_header"] is False
    assert res["has_content"] is True
    assert res["verdict"] in {"SUSPICIOUS", "MALICIOUS"}
    assert res["content_findings"]["phishing_intent"] == "HIGH"


def test_header_only_analysis():
    """Verify input with only header text and empty body analyzes correctly."""
    header = (
        'From: "Apple Billing" <billing@apple-security-check.cc>\n'
        'Return-Path: <bounce@malicious.com>\n'
        'Received-SPF: fail\n'
        'Subject: Invoice #884920'
    )
    res = email_analyzer.full_email_investigation(header, "")
    assert res["has_header"] is True
    assert res["has_content"] is False
    assert res["verdict"] in {"SUSPICIOUS", "MALICIOUS"}
    assert res["sender_check"]["is_spoofed"] is True


def test_html_body_with_mismatched_links():
    """Verify anchor text vs href link mismatch detection (brand lure to third-party domain)."""
    header = "From: newsletter@news.com\nSubject: Daily update"
    html_body = (
        '<html><body>'
        'Please log in to your account: '
        '<a href="http://evil-tracker.biz/harvest">https://www.paypal.com/signin</a>'
        '</body></html>'
    )
    res = email_analyzer.full_email_investigation(header, html_body)
    assert any("mismatch" in f.get("explanation", "").lower() or "mismatch" in f.get("title", "").lower() for f in res["findings"])
    assert any(link.get("anchor_mismatch") is True for link in res.get("links", []))


def test_analyze_email_endpoint_payload_variants(client):
    """Verify /analyze-email endpoint accepts both {header, body} and {header_text, content_text}."""
    # Payload variant 1: header & body
    r1 = client.post(
        "/analyze-email",
        json={
            "header": "From: test@example.com\nSubject: Test 1",
            "body": "Hello world"
        }
    )
    assert r1.status_code == 200
    d1 = r1.get_json()
    assert "verdict" in d1
    assert "score" in d1
    assert "auth_results" in d1
    assert "sender_check" in d1

    # Payload variant 2: header_text & content_text
    r2 = client.post(
        "/analyze-email",
        json={
            "header_text": "From: test@example.com\nSubject: Test 2",
            "content_text": "Hello world again"
        }
    )
    assert r2.status_code == 200

    # Payload variant 3: both empty rejected with 400
    r3 = client.post(
        "/analyze-email",
        json={"header": "", "body": ""}
    )
    assert r3.status_code == 400
    assert "error" in r3.get_json()


def test_email_history_persistence(client):
    """Verify email scan is stored in scan_history with source EMAIL."""
    initial_count = len(scan_history)
    client.post(
        "/analyze-email",
        json={
            "header": "From: billing@paypal.com\nSubject: Statement",
            "body": "Your monthly statement is ready."
        }
    )
    assert len(scan_history) == initial_count + 1
    last_entry = scan_history[-1]
    assert last_entry.get("source") == "EMAIL"
    assert "score" in last_entry
    assert "status" in last_entry


def test_generate_email_report_pdf(client):
    response = client.post(
        "/generate-email-report",
        json={
            "score": 90,
            "verdict": "MALICIOUS",
            "level": "High Risk Fake Email",
            "risk_factors": ["Domain mismatch", "SPF failure"],
            "header_analysis": {
                "from_header": "support@fake.com",
                "from_addr": "support@fake.com",
                "subject": "Phishing Test",
                "geo_ip": {"country": "Netherlands", "country_code": "NL"}
            },
            "content_analysis": {
                "phishing_intent": "HIGH",
                "urgency_score": 80,
                "urgency_triggers": [{"phrase": "suspended in 24 hours", "reason": "Panic"}]
            },
            "summary": {
                "authentication": "FAILED (Spoofed Domain)",
                "originating_ip": "185.220.101.5"
            }
        }
    )
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert response.data.startswith(b"%PDF")


def test_email_analyzer_page_layout_no_option_a_and_b(client):
    response = client.get("/email-analyzer")
    assert response.status_code == 200
    html = response.data.decode("utf-8")

    # Verify brand & module title
    assert "CYBERSPACE" in html
    assert "Fake Email & Header Threat Analyzer" in html

    # Verify Option A and Option B are completely removed
    assert "Option A" not in html
    assert "Option B" not in html
    assert "OPTION A" not in html
    assert "OPTION B" not in html

    # Verify core inputs and actions are present
    assert "headerInput" in html
    assert "contentInput" in html
    assert "analyzeEmailBtn" in html
    assert "Email Header & Sender Verification" in html
    assert "Email Text & Phishing Intent Analysis" in html
    assert "Spoofed PayPal" not in html


def test_parse_received_hops_timeline():
    received_headers = [
        "from mail-wm1-f41.google.com (mail-wm1-f41.google.com [209.85.128.41]) by mx.google.com with SMTP; Wed, 11 Nov 2026 12:00:15 +0000",
        "from mail.origin-relay.org (outbound.node.net [185.220.101.5]) by mail-wm1-f41.google.com with ESMTP; Wed, 11 Nov 2026 12:00:10 +0000",
        "from internal-host ([192.168.1.50]) by mail.origin-relay.org; Wed, 11 Nov 2026 12:00:00 +0000"
    ]
    hops = email_analyzer.parse_received_hops(received_headers)
    assert len(hops) == 3
    # Hop 1 is chronologically earliest (internal-host)
    assert hops[0]["hop_number"] == 1
    # Hop 2 has public IP 185.220.101.5 and is flagged as origin
    assert hops[1]["is_origin"] is True
    assert hops[1]["ip"] == "185.220.101.5"
    assert hops[1]["is_public"] is True
    # Transit delay from hop 1 to hop 2 should be +10s
    assert "+10s" in hops[1]["delay"]
    # Hop 3 delay from hop 2 is +5s
    assert "+5s" in hops[2]["delay"]
    assert hops[2]["is_origin"] is False


def test_sender_and_domain_alignment():
    # Strict alignment
    res_strict = email_analyzer.check_alignment("example.com", "example.com", "example.com")
    assert res_strict["spf_aligned"] is True
    assert res_strict["dkim_aligned"] is True
    assert res_strict["spf_mode"] == "strict"
    assert res_strict["dkim_mode"] == "strict"

    # Relaxed alignment
    res_relaxed = email_analyzer.check_alignment("sub.example.com", "example.com", "mail.sub.example.com")
    assert res_relaxed["spf_aligned"] is True
    assert res_relaxed["dkim_aligned"] is True
    assert res_relaxed["spf_mode"] == "relaxed"
    assert res_relaxed["dkim_mode"] == "relaxed"

    # Misaligned
    res_misaligned = email_analyzer.check_alignment("paypal.com", "attacker-domain.xyz", "other.org")
    assert res_misaligned["spf_aligned"] is False
    assert res_misaligned["dkim_aligned"] is False


def test_dns_spf_and_dkim_selector_check(monkeypatch):
    class MockTXTAnswer:
        def __init__(self, text):
            self.text = text
        def to_text(self):
            return f'"{self.text}"'

    class MockResolver:
        def __init__(self):
            self.lifetime = 1.0
            self.timeout = 1.0
        def resolve(self, qname, rdtype):
            qstr = str(qname)
            if rdtype == "TXT":
                if qstr == "authorized-sender.org":
                    return [MockTXTAnswer("v=spf1 ip4:198.51.100.0/24 -all")]
                elif qstr == "s1._domainkey.authorized-sender.org":
                    return [MockTXTAnswer("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD...")]
            raise Exception("NXDOMAIN")

    monkeypatch.setattr(email_analyzer.dns.resolver, "Resolver", MockResolver)

    # Test authorized IP in SPF CIDR
    spf_match = email_analyzer.check_ip_in_spf_record("authorized-sender.org", "198.51.100.42")
    assert spf_match["authorized"] is True
    assert spf_match["checked"] is True
    assert "ip4:198.51.100.0/24" in spf_match["mechanism"]

    # Test unauthorized IP
    spf_unauth = email_analyzer.check_ip_in_spf_record("authorized-sender.org", "203.0.113.99")
    assert spf_unauth["authorized"] is False
    assert spf_unauth["checked"] is True

    # Test DKIM selector record lookup
    dkim_res = email_analyzer.check_dkim_selector_record("authorized-sender.org", "s1")
    assert dkim_res["exists"] is True
    assert dkim_res["checked"] is True
    assert "s1._domainkey.authorized-sender.org" in dkim_res["target"]


def test_raw_email_mime_parsing_with_dangerous_attachments():
    raw_mime = (
        'From: "HR Payroll" <hr@spoofed-company.com>\n'
        'To: employee@company.com\n'
        'Subject: Urgent: Updated Salary Structure\n'
        'MIME-Version: 1.0\n'
        'Content-Type: multipart/mixed; boundary="BOUNDARY123"\n\n'
        '--BOUNDARY123\n'
        'Content-Type: text/plain; charset="utf-8"\n\n'
        'Please review your attached revised compensation schedule immediately.\n\n'
        '--BOUNDARY123\n'
        'Content-Type: application/octet-stream; name="Salary_Bonus_Report.pdf.exe"\n'
        'Content-Disposition: attachment; filename="Salary_Bonus_Report.pdf.exe"\n'
        'Content-Transfer-Encoding: base64\n\n'
        'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
        '--BOUNDARY123\n'
        'Content-Type: application/pdf; name="handbook.pdf"\n'
        'Content-Disposition: attachment; filename="handbook.pdf"\n'
        'Content-Transfer-Encoding: base64\n\n'
        'JVBERi0xLjQKJcTl8uXrp/Og0MTGCjQgMCBvYmoKPDwgL0xlbmd0aCA1IDAgUiA+PgpzdHJlYW0K\n'
        '--BOUNDARY123--\n'
    )

    parsed = email_analyzer.parse_raw_email_message(raw_mime)
    assert len(parsed["attachments"]) == 2

    double_ext_att = next(a for a in parsed["attachments"] if "Salary" in a["filename"])
    assert double_ext_att["is_dangerous"] is True
    assert double_ext_att["is_double_ext"] is True
    assert len(double_ext_att["sha256"]) == 64

    clean_att = next(a for a in parsed["attachments"] if a["filename"] == "handbook.pdf")
    assert clean_att["is_dangerous"] is False
    assert clean_att["is_double_ext"] is False
    assert len(clean_att["sha256"]) == 64

    # Run full investigation
    inv = email_analyzer.full_email_investigation(raw_mime, "")
    assert inv["score"] >= 70
    assert inv["verdict"] == "MALICIOUS"
    assert inv["attachment_count"] == 2
    assert any("Double-Extension" in str(f) or "Dangerous" in str(f) for f in inv["findings"])


def test_analyze_email_endpoint_eml_multipart_upload(client):
    import io
    sample_eml = (
        'From: "IT Support" <support@fake-helpdesk.com>\n'
        'Subject: Mandatory Software Update\n'
        'Received: from mail.fake-helpdesk.com ([185.220.101.88]) by mx.target.org; Wed, 11 Nov 2026 10:00:00 +0000\n'
        'Content-Type: multipart/mixed; boundary="SEP999"\n\n'
        '--SEP999\n'
        'Content-Type: text/plain\n\n'
        'Install the attached security patch immediately.\n\n'
        '--SEP999\n'
        'Content-Type: application/x-msdownload; name="patch_installer.vbs"\n'
        'Content-Disposition: attachment; filename="patch_installer.vbs"\n'
        'Content-Transfer-Encoding: base64\n\n'
        'TVo=\n'
        '--SEP999--'
    ).encode("utf-8")

    data = {
        "eml_file": (io.BytesIO(sample_eml), "security_update.eml")
    }

    res = client.post(
        "/analyze-email",
        data=data,
        content_type="multipart/form-data"
    )
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data is not None
    assert json_data["score"] >= 45
    assert json_data["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert json_data["attachment_count"] == 1
    assert json_data["attachments"][0]["filename"] == "patch_installer.vbs"
    assert json_data["attachments"][0]["is_dangerous"] is True
    assert len(json_data["hop_timeline"]) >= 1


def test_extracted_links_url_scanner_integration():
    body = (
        'Hello team,\n'
        'Please review the quarterly financial results here: https://bit.ly/fake-report-link\n'
        'Also visit our direct node http://198.51.100.22/dashboard for updates.'
    )
    content_res = email_analyzer.analyze_email_content("Financial Update", body, sender_domain="legit-corp.com")
    urls = content_res["extracted_urls"]
    assert len(urls) == 2
    # Check that shortener and IP flags are set
    shortener_link = next(u for u in urls if u["is_shortener"])
    assert shortener_link["domain"] == "bit.ly"
    ip_link = next(u for u in urls if u["is_ip"])
    assert ip_link["domain"] == "198.51.100.22"
    # Check that threat_status is populated by url scanner integration
    assert "threat_status" in shortener_link
    assert "threat_status" in ip_link


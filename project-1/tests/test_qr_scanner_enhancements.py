"""
Unit and Integration Tests for CyberScape QR Scanner Enhancements:
1. Payload type detection: URL, UPI (upi://pay), WiFi, SMS, mailto, vCard, plain text
2. Deep UPI analysis: pa, pn, am, cu parsing, pre-filled amount flags,
   payee name vs VPA mismatch, and collect-request / refund deception patterns
3. URL payload routing through full URL scanner pipeline
4. Upload Image mode: OpenCV / pyzbar multi-pass preprocessing (grayscale, threshold, resize)
   and multiple QR codes detection in one image
"""

import pytest
import io
import numpy as np
from unittest.mock import patch, MagicMock

from backend.services.qr_analyzer import (
    detect_qr_payload_type,
    parse_upi_uri,
    analyze_upi_payload,
    parse_wifi_payload,
    analyze_wifi_payload,
    analyze_general_payload,
    scan_qr_payload
)
import qr_decoder


# ---------------------------------------------------------
# 1. DETECT PAYLOAD TYPE
# ---------------------------------------------------------
def test_detect_payload_type_url():
    assert detect_qr_payload_type("https://cyberscape.security/verify") == "URL"
    assert detect_qr_payload_type("http://insecure-phish.biz/login") == "URL"
    assert detect_qr_payload_type("www.bank-login.com") == "URL"


def test_detect_payload_type_upi():
    assert detect_qr_payload_type("upi://pay?pa=store@okaxis&pn=Store&am=100") == "UPI"
    assert detect_qr_payload_type("UPI://PAY?PA=user@ybl") == "UPI"


def test_detect_payload_type_wifi():
    assert detect_qr_payload_type("WIFI:S:Guest_Network;T:WPA;P:secret123;;") == "WiFi"
    assert detect_qr_payload_type("wifi:S:OpenNet;T:nopass;;") == "WiFi"


def test_detect_payload_type_sms():
    assert detect_qr_payload_type("smsto:+919876543210:Verify your code") == "SMS"
    assert detect_qr_payload_type("sms:123456?body=HELP") == "SMS"


def test_detect_payload_type_mailto():
    assert detect_qr_payload_type("mailto:security-alert@company.com?subject=Urgent") == "mailto"


def test_detect_payload_type_vcard():
    vcard = "BEGIN:VCARD\nVERSION:3.0\nFN:Alice Smith\nTEL:123456789\nEND:VCARD"
    assert detect_qr_payload_type(vcard) == "vCard"
    assert detect_qr_payload_type("MECARD:N:Smith,Alice;TEL:123456789;;") == "vCard"


def test_detect_payload_type_plain_text():
    assert detect_qr_payload_type("Welcome to CyberScape Conference 2026") == "plain text"
    assert detect_qr_payload_type("A1-B2-C3-D4 serial number token") == "plain text"


# ---------------------------------------------------------
# 2. UPI FORENSIC ANALYSIS
# ---------------------------------------------------------
def test_upi_uri_parsing():
    uri = "upi://pay?pa=merchant%40okhdfcbank&pn=SuperMarket&am=450.50&cu=INR&tn=Groceries&tr=TXN102938"
    parsed = parse_upi_uri(uri)
    assert parsed["pa"] == "merchant@okhdfcbank"
    assert parsed["pn"] == "SuperMarket"
    assert parsed["am"] == 450.50
    assert parsed["cu"] == "INR"
    assert parsed["tn"] == "Groceries"
    assert parsed["tr"] == "TXN102938"


def test_upi_prefilled_amount_warning():
    # Moderate pre-filled amount (< 5000)
    uri = "upi://pay?pa=shop@okaxis&pn=Coffee%20Shop&am=250.00&cu=INR"
    report = analyze_upi_payload(uri)
    assert any(s["id"] == "upi_prefilled_amount" for s in report["signals"])
    assert report["score"] == 25
    assert report["status"] == "SAFE" or report["status"] == "SUSPICIOUS"


def test_upi_high_prefilled_amount_critical():
    # High pre-filled amount (>= 5000)
    uri = "upi://pay?pa=vendor@okaxis&pn=Wholesale&am=15000.00&cu=INR"
    report = analyze_upi_payload(uri)
    assert any(s["id"] == "upi_high_prefilled_amount" for s in report["signals"])
    assert report["score"] >= 45


def test_upi_payee_name_vs_vpa_mismatch_impersonation():
    # Payee claims to be electricity board, but VPA is a personal account
    uri = "upi://pay?pa=rahul.sharma829@ybl&pn=State%20Electricity%20Bill%20Support&am=1200&cu=INR"
    report = analyze_upi_payload(uri)
    assert any(s["id"] == "upi_payee_vpa_mismatch" for s in report["signals"])
    mismatch_sig = [s for s in report["signals"] if s["id"] == "upi_payee_vpa_mismatch"][0]
    assert mismatch_sig["severity"] == "critical"
    assert "rahul.sharma829@ybl" in mismatch_sig["evidence"]
    assert report["score"] >= 65


def test_upi_collect_request_refund_deception():
    # Deceptive collect/refund scam where victim is told they will receive money
    uri = "upi://pay?pa=refund-agent@okaxis&pn=Customer%20Care&am=2000&cu=INR&tn=Scan%20to%20receive%20cashback%20refund"
    report = analyze_upi_payload(uri)
    assert any(s["id"] == "upi_collect_deception" for s in report["signals"])
    deception_sig = [s for s in report["signals"] if s["id"] == "upi_collect_deception"][0]
    assert deception_sig["severity"] == "critical"
    assert report["status"] == "MALICIOUS"
    assert report["score"] >= 85


def test_upi_clean_dynamic_payment():
    # Standard clean merchant QR with no pre-filled amount
    uri = "upi://pay?pa=metro.station@axisbank&pn=Metro%20Transit&cu=INR"
    report = analyze_upi_payload(uri)
    assert any(s["id"] == "upi_clean_structure" for s in report["signals"])
    assert report["status"] == "SAFE"
    assert report["score"] == 0


# ---------------------------------------------------------
# 3. URL ROUTING THROUGH FULL URL SCANNER PIPELINE
# ---------------------------------------------------------
def test_scan_qr_payload_routes_url_through_pipeline():
    with patch("backend.services.qr_analyzer.scan_url") as mock_scan_url:
        mock_scan_url.return_value = {
            "url": "https://malicious-login.top/account",
            "score": 90,
            "status": "MALICIOUS",
            "level": "High Risk",
            "signals": [{"id": "urlhaus_malicious", "severity": "critical", "score_impact": 85}],
            "sources_checked": {"urlhaus": {"status": "FLAGGED", "available": True}}
        }

        report = scan_qr_payload("https://malicious-login.top/account")
        assert mock_scan_url.called
        assert report["source"] == "QR"
        assert report["payload_type"] == "URL"
        assert report["status"] == "MALICIOUS"
        assert report["score"] == 90


def test_scan_qr_payload_routes_bare_domain_as_https_url():
    with patch("backend.services.qr_analyzer.scan_url") as mock_scan_url:
        mock_scan_url.return_value = {
            "url": "https://www.google.com",
            "score": 0,
            "status": "SAFE",
            "level": "Low Risk",
            "signals": []
        }

        report = scan_qr_payload("www.google.com")
        mock_scan_url.assert_called_with("https://www.google.com")
        assert report["source"] == "QR"
        assert report["payload_type"] == "URL"


# ---------------------------------------------------------
# 4. UPLOAD IMAGE MODE: PREPROCESSING & MULTI-QR DETECTION
# ---------------------------------------------------------
def test_qr_decoder_multi_pass_and_multi_qr_support():
    # Mock cv2 and pyzbar to simulate detecting multiple QR codes across passes
    mock_detector = MagicMock()
    mock_detector.detectAndDecodeMulti.return_value = (
        True,
        ["https://first-qr.example.com", "upi://pay?pa=second@okaxis"],
        None,
        None
    )

    with patch("cv2.imdecode", return_value=np.zeros((300, 300, 3), dtype=np.uint8)):
        with patch("cv2.QRCodeDetector", return_value=mock_detector):
            fake_bytes = b"fake-png-bytes"
            res = qr_decoder.decode_qr_image_bytes(fake_bytes)

            assert res["success"] is True
            assert res["count"] == 2
            assert "https://first-qr.example.com" in res["all_payloads"]
            assert "upi://pay?pa=second@okaxis" in res["all_payloads"]
            assert res["data"] == "https://first-qr.example.com"
            assert res["payload_type"] == "URL"


def test_qr_decoder_handles_low_light_clahe_preprocessing():
    # Test that when pass 1 returns empty, subsequent CLAHE / Otsu passes decode the QR
    mock_detector = MagicMock()
    # Pass 1 raw fails, but Pass 3 CLAHE succeeds
    mock_detector.detectAndDecodeMulti.side_effect = [
        (False, [], None, None),  # Pass 1: raw
        (False, [], None, None),  # Pass 2: gray
        (True, ["https://rescued-from-lowlight.org"], None, None),  # Pass 3: CLAHE
    ]
    mock_detector.detectAndDecode.return_value = ("", None, None)

    with patch("cv2.imdecode", return_value=np.zeros((400, 400, 3), dtype=np.uint8)):
        with patch("cv2.QRCodeDetector", return_value=mock_detector):
            with patch("qr_decoder.HAS_PYZBAR", False):
                res = qr_decoder.decode_qr_image_bytes(b"dark-image-bytes")
                assert res["success"] is True
                assert res["data"] == "https://rescued-from-lowlight.org"
                assert "CLAHE" in res["engine"] or "OpenCV" in res["engine"]


def test_qr_decoder_unsharp_masking_for_blurry_images():
    # Test that deblurring pass successfully catches blurry QRs
    mock_detector = MagicMock()
    # Raw, gray, clahe, otsu, adaptive fail; unsharp sharpening succeeds
    mock_detector.detectAndDecodeMulti.side_effect = [
        (False, [], None, None),
        (False, [], None, None),
        (False, [], None, None),
        (False, [], None, None),
        (False, [], None, None),
        (True, ["https://sharpened-from-blur.net"], None, None),
    ]
    mock_detector.detectAndDecode.return_value = ("", None, None)

    with patch("cv2.imdecode", return_value=np.zeros((500, 500, 3), dtype=np.uint8)):
        with patch("cv2.QRCodeDetector", return_value=mock_detector):
            with patch("qr_decoder.HAS_PYZBAR", False):
                res = qr_decoder.decode_qr_image_bytes(b"blurry-image-bytes")
                assert res["success"] is True
                assert res["data"] == "https://sharpened-from-blur.net"


def test_qr_decoder_empty_input_graceful():
    res = qr_decoder.decode_qr_image_bytes(b"")
    assert res["success"] is False
    assert res["count"] == 0
    assert len(res["all_payloads"]) == 0


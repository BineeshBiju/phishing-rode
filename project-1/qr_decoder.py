"""
CyberScape Advanced QR Code Sandbox Decoder
Decodes QR codes using OpenCV and pyzbar with comprehensive multi-pass image preprocessing:
- Grayscale conversion
- Contrast Limited Adaptive Histogram Equalization (CLAHE) for low-light / high glare
- Otsu & Adaptive Gaussian binarization thresholding
- Unsharp masking / sharpening for blurry images
- Dynamic upscaling and downscaling for extreme resolution images
- Multi-QR detection support (finds and returns all QR codes in an image)
"""

import io
import os
import base64
from pathlib import Path
import numpy as np
from PIL import Image

# Ensure pyzbar DLLs can be located on Windows
pyzbar_dir = Path(__file__).parent / ".venv" / "Lib" / "site-packages" / "pyzbar"
if pyzbar_dir.exists():
    if hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(str(pyzbar_dir.resolve()))
        except Exception:
            pass
    os.environ["PATH"] = str(pyzbar_dir.resolve()) + ";" + os.environ.get("PATH", "")

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from pyzbar import pyzbar
    HAS_PYZBAR = True
except Exception:
    pyzbar = None
    HAS_PYZBAR = False

from backend.services.qr_analyzer import detect_qr_payload_type


def _extract_from_opencv(detector, image_np, unique_set: set, ordered_list: list):
    """Run OpenCV detector with multi-QR support on numpy image array."""
    if detector is None or image_np is None:
        return

    try:
        # 1. Try detectAndDecodeMulti (built into OpenCV)
        if hasattr(detector, "detectAndDecodeMulti"):
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(image_np)
            if retval and decoded_info:
                for text in decoded_info:
                    val = (text or "").strip()
                    if val and val not in unique_set:
                        unique_set.add(val)
                        ordered_list.append(val)
    except Exception:
        pass

    try:
        # 2. Try single detectAndDecode fallback
        data, _, _ = detector.detectAndDecode(image_np)
        val = (data or "").strip()
        if val and val not in unique_set:
            unique_set.add(val)
            ordered_list.append(val)
    except Exception:
        pass


def _extract_from_pyzbar(image_variant, unique_set: set, ordered_list: list):
    """Run pyzbar on numpy or PIL image variant."""
    if not HAS_PYZBAR or image_variant is None:
        return

    try:
        decoded_objects = pyzbar.decode(image_variant)
        for obj in decoded_objects:
            if obj.data:
                try:
                    val = obj.data.decode("utf-8", errors="replace").strip()
                except Exception:
                    val = str(obj.data).strip()
                if val and val not in unique_set:
                    unique_set.add(val)
                    ordered_list.append(val)
    except Exception:
        pass


def decode_qr_image_bytes(image_bytes: bytes) -> dict:
    """
    Decode one or multiple QR codes from raw image bytes using multi-pass
    OpenCV and pyzbar preprocessing pipelines.
    """
    if not image_bytes:
        return {"success": False, "error": "Empty image data received", "count": 0, "all_payloads": []}

    unique_payloads = set()
    ordered_payloads = []
    used_engine = ""

    # Decode image to OpenCV BGR format
    img_cv = None
    if HAS_CV2:
        try:
            nparr = np.frombuffer(image_bytes, np.uint8)
            img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        except Exception:
            img_cv = None

    # Load PIL image
    pil_image = None
    try:
        pil_image = Image.open(io.BytesIO(image_bytes))
    except Exception:
        pass

    detector = cv2.QRCodeDetector() if HAS_CV2 else None

    # PASS 1: Raw Original Image (pyzbar + OpenCV)
    if pil_image:
        _extract_from_pyzbar(pil_image, unique_payloads, ordered_payloads)
    if img_cv is not None:
        _extract_from_opencv(detector, img_cv, unique_payloads, ordered_payloads)

    if ordered_payloads and not used_engine:
        used_engine = "Standard Direct Decoder"

    # If already found or if we need further preprocessing for degraded images
    if img_cv is not None:
        h, w = img_cv.shape[:2]

        # PASS 2: Grayscale Conversion
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        _extract_from_opencv(detector, gray, unique_payloads, ordered_payloads)
        if pil_image:
            _extract_from_pyzbar(gray, unique_payloads, ordered_payloads)
        if ordered_payloads and not used_engine:
            used_engine = "OpenCV-Grayscale"

        # PASS 3: Contrast Limited Adaptive Histogram Equalization (CLAHE)
        # Highly effective for dark, low-light, or glare-shadowed images
        try:
            clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
            clahe_img = clahe.apply(gray)
            prev_len = len(ordered_payloads)
            _extract_from_opencv(detector, clahe_img, unique_payloads, ordered_payloads)
            _extract_from_pyzbar(clahe_img, unique_payloads, ordered_payloads)
            if not used_engine and len(ordered_payloads) > prev_len:
                used_engine = "OpenCV-CLAHE-LowLight"
        except Exception:
            pass

        # PASS 4: Otsu Binarization (Thresholding)
        try:
            _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            prev_len = len(ordered_payloads)
            _extract_from_opencv(detector, otsu, unique_payloads, ordered_payloads)
            _extract_from_pyzbar(otsu, unique_payloads, ordered_payloads)
            if not used_engine and len(ordered_payloads) > prev_len:
                used_engine = "OpenCV-OtsuThreshold"
        except Exception:
            pass

        # PASS 5: Adaptive Gaussian Thresholding (for localized uneven shadows)
        try:
            adaptive = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 10
            )
            prev_len = len(ordered_payloads)
            _extract_from_opencv(detector, adaptive, unique_payloads, ordered_payloads)
            _extract_from_pyzbar(adaptive, unique_payloads, ordered_payloads)
            if not used_engine and len(ordered_payloads) > prev_len:
                used_engine = "OpenCV-AdaptiveThreshold"
        except Exception:
            pass

        # PASS 6: Unsharp Masking / Deblurring Filter
        # Sharpens out-of-focus and blurry QR edges
        try:
            blurred = cv2.GaussianBlur(gray, (0, 0), 2.0)
            unsharp = cv2.addWeighted(gray, 1.6, blurred, -0.6, 0)
            prev_len = len(ordered_payloads)
            _extract_from_opencv(detector, unsharp, unique_payloads, ordered_payloads)
            _extract_from_pyzbar(unsharp, unique_payloads, ordered_payloads)
            if not used_engine and len(ordered_payloads) > prev_len:
                used_engine = "OpenCV-UnsharpSharpening"
        except Exception:
            pass

        # PASS 7: Resolution Scaling (Resize tiny or very large images)
        if len(ordered_payloads) == 0:
            try:
                # Upscale if low resolution (< 400px)
                if min(w, h) < 400:
                    scaled = cv2.resize(gray, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)
                    _extract_from_opencv(detector, scaled, unique_payloads, ordered_payloads)
                    _extract_from_pyzbar(scaled, unique_payloads, ordered_payloads)
                    if ordered_payloads:
                        used_engine = "OpenCV-Upscaled"
                # Downscale if massive (> 1800px)
                elif max(w, h) > 1800:
                    scale_factor = 1200.0 / max(w, h)
                    scaled = cv2.resize(gray, None, fx=scale_factor, fy=scale_factor, interpolation=cv2.INTER_AREA)
                    _extract_from_opencv(detector, scaled, unique_payloads, ordered_payloads)
                    _extract_from_pyzbar(scaled, unique_payloads, ordered_payloads)
                    if ordered_payloads:
                        used_engine = "OpenCV-Downscaled"
            except Exception:
                pass

        # PASS 8: Morphological Clean-up (closing gaps in broken modules)
        if len(ordered_payloads) == 0:
            try:
                kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
                morphed = cv2.morphologyEx(gray, cv2.MORPH_CLOSE, kernel)
                _extract_from_opencv(detector, morphed, unique_payloads, ordered_payloads)
                _extract_from_pyzbar(morphed, unique_payloads, ordered_payloads)
                if ordered_payloads:
                    used_engine = "OpenCV-Morphology"
            except Exception:
                pass

    if ordered_payloads:
        primary = ordered_payloads[0]
        return {
            "success": True,
            "data": primary,
            "all_payloads": ordered_payloads,
            "count": len(ordered_payloads),
            "payload_type": detect_qr_payload_type(primary),
            "engine": used_engine or "OpenCV/pyzbar"
        }

    return {
        "success": False,
        "error": "No QR code could be detected from the image. Please ensure the QR is clear and well-lit.",
        "count": 0,
        "all_payloads": []
    }


def decode_qr_base64(data_uri_or_b64: str) -> dict:
    """Decode QR code from base64 string or data URI."""
    if not data_uri_or_b64:
        return {"success": False, "error": "No image data provided", "count": 0, "all_payloads": []}

    clean_b64 = data_uri_or_b64
    if "," in clean_b64:
        clean_b64 = clean_b64.split(",", 1)[1]

    try:
        raw_bytes = base64.b64decode(clean_b64)
        return decode_qr_image_bytes(raw_bytes)
    except Exception as e:
        return {"success": False, "error": f"Invalid base64 image data: {str(e)}", "count": 0, "all_payloads": []}

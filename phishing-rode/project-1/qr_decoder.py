"""
CyberScape Advanced QR Code Sandbox Decoder
Decodes QR codes using OpenCV (cv2.QRCodeDetector) with pyzbar and Pillow fallbacks.
Supports direct image upload (bytes/stream) and base64 strings.
"""

import io
import base64
import numpy as np
from PIL import Image

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


def decode_qr_image_bytes(image_bytes: bytes) -> dict:
    """Decode QR code payload from raw image bytes."""
    if not image_bytes:
        return {"success": False, "error": "Empty image data received"}

    # Attempt OpenCV decoding first
    if HAS_CV2:
        try:
            nparr = np.frombuffer(image_bytes, np.uint8)
            img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img_cv is not None:
                detector = cv2.QRCodeDetector()
                data, points, _ = detector.detectAndDecode(img_cv)
                if data:
                    return {"success": True, "data": data.strip(), "engine": "OpenCV"}
                
                # Try with grayscale/contrast enhancement
                gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
                data, _, _ = detector.detectAndDecode(gray)
                if data:
                    return {"success": True, "data": data.strip(), "engine": "OpenCV-Enhanced"}
        except Exception:
            pass

    # Attempt pyzbar decoding
    if HAS_PYZBAR:
        try:
            pil_image = Image.open(io.BytesIO(image_bytes))
            decoded_objects = pyzbar.decode(pil_image)
            for obj in decoded_objects:
                if obj.data:
                    return {
                        "success": True,
                        "data": obj.data.decode("utf-8", errors="replace").strip(),
                        "engine": "pyzbar"
                    }
        except Exception:
            pass

    # Fallback attempt with Pillow and OpenCV after resizing if image was very high resolution
    if HAS_CV2:
        try:
            pil_image = Image.open(io.BytesIO(image_bytes))
            pil_image.thumbnail((800, 800))
            buffered = io.BytesIO()
            pil_image.save(buffered, format="PNG")
            nparr = np.frombuffer(buffered.getvalue(), np.uint8)
            img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img_cv is not None:
                detector = cv2.QRCodeDetector()
                data, _, _ = detector.detectAndDecode(img_cv)
                if data:
                    return {"success": True, "data": data.strip(), "engine": "OpenCV-Rescaled"}
        except Exception:
            pass

    return {
        "success": False,
        "error": "No QR code could be detected or decoded from the image. Please ensure the QR is clear and well-lit."
    }


def decode_qr_base64(data_uri_or_b64: str) -> dict:
    """Decode QR code from base64 string or data URI."""
    if not data_uri_or_b64:
        return {"success": False, "error": "No image data provided"}

    clean_b64 = data_uri_or_b64
    if "," in clean_b64:
        clean_b64 = clean_b64.split(",", 1)[1]

    try:
        raw_bytes = base64.b64decode(clean_b64)
        return decode_qr_image_bytes(raw_bytes)
    except Exception as e:
        return {"success": False, "error": f"Invalid base64 image data: {str(e)}"}

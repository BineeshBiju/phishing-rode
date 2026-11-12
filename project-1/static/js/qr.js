/*
 * Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
 * See LICENSE for details.
 */
/**
 * CYBERSPACE — Enhanced QR Code Scanner
 * Supports Dual Mode: Live Webcam Scanning (jsQR / BarcodeDetector) & File Upload
 */

let extractedUrl = "";
let cameraStream = null;
let animationFrameId = null;
let isScanning = false;
let currentMode = "camera";

// DOM Elements
const tabCamera = document.getElementById("tabCameraScan");
const tabUpload = document.getElementById("tabFileUpload");
const modeCameraPanel = document.getElementById("modeCamera");
const modeUploadPanel = document.getElementById("modeUpload");

const videoEl = document.getElementById("qrVideo");
const canvasEl = document.getElementById("qrCanvas");
const cameraIdlePlaceholder = document.getElementById("cameraIdlePlaceholder");
const scannerReticle = document.getElementById("scannerReticle");
const cameraToggleBtn = document.getElementById("cameraToggleBtn");
const cameraToggleIcon = document.getElementById("cameraToggleIcon");
const cameraToggleText = document.getElementById("cameraToggleText");
const cameraSelect = document.getElementById("cameraSelect");
const cameraStatusEl = document.getElementById("cameraStatus");

const fileInput = document.getElementById("qrFile");
const dropZone = document.getElementById("dropZone");
const uploadStatusEl = document.getElementById("qrStatus");

const destInput = document.getElementById("qrDestinationInput");
const clearDestBtn = document.getElementById("btnClearDest");
const analyzeBtn = document.getElementById("analyzeQr");
const quickStatusEl = document.getElementById("qrQuickStatus");
const outEl = document.getElementById("qrResult");

/**
 * Play a gentle, crisp audio confirmation tone using Web Audio API
 */
function playBeepTone() {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.type = "sine";
    osc.frequency.setValueAtTime(880, ctx.currentTime); // 880 Hz (A5 musical pitch)
    gain.gain.setValueAtTime(0.12, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.16);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + 0.18);
  } catch (err) {
    console.debug("Web Audio tone playback notice:", err);
  }
}

/**
 * Switch between Live Camera Scan and Upload Image tabs
 */
function switchQrMode(mode) {
  currentMode = mode;

  if (mode === "camera") {
    if (tabCamera) {
      tabCamera.className = "px-4 py-1.5 rounded-chip text-sm font-semibold transition-colors bg-ink text-ground cursor-pointer";
    }
    if (tabUpload) {
      tabUpload.className = "px-4 py-1.5 rounded-chip text-sm font-medium transition-colors text-muted hover:text-ink cursor-pointer";
    }
    if (modeCameraPanel) modeCameraPanel.style.display = "flex";
    if (modeUploadPanel) modeUploadPanel.style.display = "none";
  } else {
    if (tabCamera) {
      tabCamera.className = "px-4 py-1.5 rounded-chip text-sm font-medium transition-colors text-muted hover:text-ink cursor-pointer";
    }
    if (tabUpload) {
      tabUpload.className = "px-4 py-1.5 rounded-chip text-sm font-semibold transition-colors bg-ink text-ground cursor-pointer";
    }
    if (modeCameraPanel) modeCameraPanel.style.display = "none";
    if (modeUploadPanel) modeUploadPanel.style.display = "flex";
    // Turn off live camera if leaving camera tab to save battery and camera locks
    stopCamera();
  }
}

/**
 * Enumerate available video input hardware devices
 */
async function enumerateCameras() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    const videoDevices = devices.filter(d => d.kind === "videoinput");

    if (cameraSelect) {
      cameraSelect.innerHTML = "";
      if (videoDevices.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "Default Camera (Auto)";
        cameraSelect.appendChild(opt);
      } else {
        videoDevices.forEach((dev, idx) => {
          const opt = document.createElement("option");
          opt.value = dev.deviceId;
          opt.textContent = dev.label || `Camera ${idx + 1} (${dev.deviceId.slice(0, 5)}...)`;
          cameraSelect.appendChild(opt);
        });
      }
    }
  } catch (err) {
    console.debug("Camera enumeration error:", err);
  }
}

/**
 * Start Live Webcam Stream
 */
async function startCamera() {
  if (isScanning) return;
  setCameraStatus("Requesting webcam access...", "normal");

  const selectedDeviceId = cameraSelect && cameraSelect.value ? cameraSelect.value : undefined;
  const constraints = {
    video: selectedDeviceId
      ? { deviceId: { exact: selectedDeviceId } }
      : { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } }
  };

  try {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error("Webcam access is not supported by your browser environment.");
    }

    cameraStream = await navigator.mediaDevices.getUserMedia(constraints);
    videoEl.srcObject = cameraStream;
    videoEl.setAttribute("playsinline", "true");
    await videoEl.play();

    isScanning = true;
    videoEl.style.display = "block";
    cameraIdlePlaceholder.style.display = "none";
    scannerReticle.style.display = "flex";
    cameraToggleText.textContent = "Stop Camera";
    cameraToggleIcon.innerHTML = '<i data-lucide="square" class="w-3.5 h-3.5"></i>';
    if (window.lucide && typeof window.lucide.createIcons === "function") lucide.createIcons();
    setCameraStatus("Scanning for QR codes...", "scanning");

    requestAnimationFrame(scanVideoFrame);
  } catch (err) {
    console.error("Camera access error:", err);
    stopCamera();
    setCameraStatus("Camera Error: " + err.message + ". Check browser permissions or try uploading an image.", "error");
  }
}

/**
 * Stop Live Webcam Stream
 */
function stopCamera() {
  isScanning = false;
  if (animationFrameId) {
    cancelAnimationFrame(animationFrameId);
    animationFrameId = null;
  }

  if (cameraStream) {
    cameraStream.getTracks().forEach(track => {
      try { track.stop(); } catch (e) {}
    });
    cameraStream = null;
  }

  if (videoEl) {
    videoEl.pause();
    videoEl.srcObject = null;
    videoEl.style.display = "none";
  }

  if (scannerReticle) scannerReticle.style.display = "none";
  if (cameraIdlePlaceholder) cameraIdlePlaceholder.style.display = "flex";

  if (cameraToggleBtn) {
    cameraToggleBtn.classList.remove("camera-active");
    cameraToggleIcon.innerHTML = '<i data-lucide="play" class="w-3.5 h-3.5"></i>';
    if (window.lucide && typeof window.lucide.createIcons === "function") lucide.createIcons();
    cameraToggleText.textContent = "Start Camera";
  }
}

/**
 * Toggle Start / Stop Camera
 */
function toggleCamera() {
  if (isScanning) {
    stopCamera();
  } else {
    startCamera();
  }
}

/**
 * Handle Camera Device Switch
 */
function onCameraDeviceChanged() {
  if (isScanning) {
    stopCamera();
    startCamera();
  }
}

/**
 * Scan video frame using BarcodeDetector or jsQR
 */
async function scanVideoFrame() {
  if (!isScanning || !videoEl) return;

  if (videoEl.readyState === videoEl.HAVE_ENOUGH_DATA) {
    const width = videoEl.videoWidth;
    const height = videoEl.videoHeight;

    if (width > 0 && height > 0) {
      let detectedCode = null;

      // 1. Try browser-native BarcodeDetector if available (hardware accelerated)
      if ("BarcodeDetector" in window) {
        try {
          const barcodeDetector = new window.BarcodeDetector({ formats: ["qr_code"] });
          const barcodes = await barcodeDetector.detect(videoEl);
          if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
            detectedCode = barcodes[0].rawValue.trim();
          }
        } catch (e) {
          // Fall through to jsQR
        }
      }

      // 2. Try client-side jsQR engine
      if (!detectedCode && window.jsQR) {
        try {
          canvasEl.width = width;
          canvasEl.height = height;
          const ctx = canvasEl.getContext("2d", { willReadFrequently: true });
          ctx.drawImage(videoEl, 0, 0, width, height);
          const imgData = ctx.getImageData(0, 0, width, height);
          const qr = window.jsQR(imgData.data, width, height, { inversionAttempts: "attemptBoth" });
          if (qr && qr.data) {
            detectedCode = qr.data.trim();
          }
        } catch (e) {
          console.debug("Frame decode error:", e);
        }
      }

      // Auto-Detect Trigger: Automatically pass to live threat intelligence pipeline
      if (detectedCode) {
        playBeepTone();
        stopCamera();
        setExtractedUrl(detectedCode);
        setCameraStatus(`QR Code detected: ${detectedCode.slice(0, 40)}...`, "success");
        autoInspectQr(detectedCode);
        return;
      }
    }
  }

  // Continue scanning loop
  if (isScanning) {
    animationFrameId = requestAnimationFrame(scanVideoFrame);
  }
}

/**
 * Set and display the extracted destination URL
 */
function setExtractedUrl(url) {
  extractedUrl = (url || "").trim();
  if (destInput) {
    destInput.value = extractedUrl;
  }
  if (clearDestBtn) {
    clearDestBtn.style.display = extractedUrl ? "block" : "none";
  }
  if (analyzeBtn) {
    analyzeBtn.disabled = !extractedUrl;
  }
}

/**
 * Handle manual edits to the destination input box
 */
function handleDestinationInputChange() {
  if (!destInput) return;
  extractedUrl = destInput.value.trim();
  if (clearDestBtn) {
    clearDestBtn.style.display = extractedUrl ? "block" : "none";
  }
  if (analyzeBtn) {
    analyzeBtn.disabled = !extractedUrl;
  }
}

/**
 * Clear extracted destination input box
 */
function clearExtractedDestination() {
  setExtractedUrl("");
  if (quickStatusEl) {
    quickStatusEl.style.display = "none";
    quickStatusEl.innerHTML = "";
  }
  const rootEl = document.getElementById("qrScanResultRoot") || outEl;
  if (window.CyberScapeReact && typeof window.CyberScapeReact.renderScanResult === "function" && rootEl) {
    window.CyberScapeReact.renderScanResult(rootEl, { state: "idle" });
  } else if (outEl) {
    outEl.className = "result hidden";
    outEl.innerHTML = "";
  }
  if (destInput) destInput.focus();
}

/**
 * Helper to update camera status text
 */
function setCameraStatus(msg, type = "normal") {
  if (!cameraStatusEl) return;
  cameraStatusEl.className = "text-xs font-mono pt-2 " + 
    (type === "error" ? "text-danger" : (type === "success" ? "text-safe font-semibold" : (type === "scanning" ? "text-line/90 animate-pulse" : "text-line/60")));
  cameraStatusEl.textContent = msg;
}

/**
 * Helper to update file upload status text
 */
function setUploadStatus(msg, type = "normal") {
  if (!uploadStatusEl) return;
  uploadStatusEl.className = "text-xs font-mono mt-3 " + 
    (type === "error" ? "text-danger" : (type === "success" ? "text-safe font-semibold" : "text-line/60"));
  uploadStatusEl.textContent = msg;
}

/**
 * Render multi-QR selector pills when an image contains more than one QR code
 */
function renderMultipleQrPills(payloads, selected) {
  const container = document.getElementById("multiQrContainer");
  if (!container) return;

  container.style.display = "flex";
  container.innerHTML = "";

  const label = document.createElement("span");
  label.className = "text-[11px] font-mono text-line/80 font-semibold block w-full mb-1";
  label.textContent = `Multiple QR Codes Found (${payloads.length}):`;
  container.appendChild(label);

  payloads.forEach((payload, idx) => {
    const btn = document.createElement("button");
    btn.type = "button";
    const isSel = payload === selected;
    btn.className = `px-2.5 py-1 text-xs font-mono rounded border transition-colors cursor-pointer text-left ${
      isSel
        ? "bg-ground text-ink border-ground font-bold"
        : "bg-inkSoft text-line/80 border-inkLine hover:border-line hover:text-ground"
    }`;

    let typeTag = "RAW";
    const lower = payload.toLowerCase();
    if (lower.startsWith("upi://")) typeTag = "UPI";
    else if (lower.startsWith("http://") || lower.startsWith("https://")) typeTag = "URL";
    else if (lower.startsWith("wifi:")) typeTag = "WIFI";
    else if (lower.startsWith("smsto:") || lower.startsWith("sms:")) typeTag = "SMS";
    else if (lower.startsWith("mailto:")) typeTag = "MAIL";
    else if (lower.includes("vcard")) typeTag = "VCARD";

    const preview = payload.length > 28 ? payload.slice(0, 28) + "..." : payload;
    btn.textContent = `[${typeTag}] QR ${idx + 1}: ${preview}`;

    btn.onclick = (e) => {
      e.stopPropagation();
      setExtractedUrl(payload);
      renderMultipleQrPills(payloads, payload);
      autoInspectQr(payload);
    };

    container.appendChild(btn);
  });
}

/**
 * Handle File Upload (Drag & Drop or File Picker)
 */
async function handleQrImageFile(file) {
  if (!file) return;

  // Intercept unauthenticated users
  if (window.CYBER_AUTH && !window.CYBER_AUTH.isAuthenticated) {
    window.location.href = (window.CYBER_AUTH && window.CYBER_AUTH.loginUrl) || "/login";
    return;
  }

  setUploadStatus(`Analyzing "${file.name}" (${(file.size / 1024).toFixed(1)} KB) with OpenCV / pyzbar engine...`);
  setExtractedUrl("");

  const multiContainer = document.getElementById("multiQrContainer");
  if (multiContainer) {
    multiContainer.style.display = "none";
    multiContainer.innerHTML = "";
  }

  const rootEl = document.getElementById("qrScanResultRoot") || outEl;
  if (window.CyberScapeReact && typeof window.CyberScapeReact.renderScanResult === "function" && rootEl) {
    window.CyberScapeReact.renderScanResult(rootEl, { state: "idle" });
  } else if (outEl) {
    outEl.className = "result hidden";
  }

  // Use server-side OpenCV & pyzbar engine with CLAHE, Otsu thresholding, sharpening, and multi-QR detection
  try {
    const formData = new FormData();
    formData.append("qr_file", file);

    const res = await fetch("/decode-qr", {
      method: "POST",
      body: formData
    });
    const data = await res.json();

    if (res.ok && data.success && data.data) {
      playBeepTone();
      setExtractedUrl(data.data);

      if (data.count > 1 && Array.isArray(data.all_payloads)) {
        setUploadStatus(`Detected ${data.count} QR codes in this image (${data.engine}). Analyzing primary code.`, "success");
        renderMultipleQrPills(data.all_payloads, data.data);
      } else {
        const typeLabel = data.payload_type || "Payload";
        setUploadStatus(`QR code decoded [${typeLabel}] via ${data.engine}: ${data.data.slice(0, 45)}...`, "success");
      }
      autoInspectQr(data.data);
    } else {
      // Fallback: Try client-side canvas decode if server returned no QR
      const objectUrl = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        try {
          const c = document.createElement("canvas");
          const ctx = c.getContext("2d", { willReadFrequently: true });
          c.width = img.naturalWidth;
          c.height = img.naturalHeight;
          ctx.drawImage(img, 0, 0);
          const imgData = ctx.getImageData(0, 0, c.width, c.height);
          if (window.jsQR) {
            const qr = window.jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: "attemptBoth" });
            if (qr && qr.data) {
              playBeepTone();
              setExtractedUrl(qr.data);
              setUploadStatus(`QR code decoded via client fallback: ${qr.data.slice(0, 45)}...`, "success");
              autoInspectQr(qr.data);
              URL.revokeObjectURL(objectUrl);
              return;
            }
          }
        } catch (e) {}
        URL.revokeObjectURL(objectUrl);
        setUploadStatus(data.error || "Could not detect a valid QR code in this image. Try another image.", "error");
      };
      img.onerror = () => {
        URL.revokeObjectURL(objectUrl);
        setUploadStatus(data.error || "Could not decode QR code.", "error");
      };
      img.src = objectUrl;
    }
  } catch (err) {
    setUploadStatus("Decoding service error: " + err.message, "error");
  }
}

/**
 * Automatically pass decoded QR destination to the live threat intelligence pipeline
 */
async function autoInspectQr(destinationUrl) {
  let url = (destinationUrl || "").trim();
  if (!url) return;

  const qrRoot = document.getElementById("qrScanResultRoot") || outEl;

  // Intercept unauthenticated users
  if (window.CYBER_AUTH && !window.CYBER_AUTH.isAuthenticated) {
    window.location.href = (window.CYBER_AUTH && window.CYBER_AUTH.loginUrl) || "/login";
    return;
  }

  // Auto-prefix https:// only if it looks like a standard web domain without protocol
  if (!/^[a-zA-Z0-9+.-]+:\/\//i.test(url) && !/^(wifi:|smsto:|sms:|mailto:|begin:vcard|mecard:)/i.test(url)) {
    if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/i.test(url)) {
      url = "https://" + url;
      setExtractedUrl(url);
    }
  }

  if (analyzeBtn) analyzeBtn.disabled = true;

  // IMMEDIATELY clear previous report and show full-width skeleton
  if (window.CyberScapeReact && typeof window.CyberScapeReact.renderScanResult === "function" && qrRoot) {
    window.CyberScapeReact.renderScanResult(qrRoot, {
      state: "loading",
      url: url
    });
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 20000);

  try {
    const res = await fetch("/qr-result", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      let errMsg = "QR threat inspection failed.";
      try {
        const errJson = await res.json();
        errMsg = errJson.error || errMsg;
      } catch (e) {}
      throw new Error(errMsg);
    }

    const data = await res.json();

    // Render full-width rectangular ScanResultPanel
    if (window.CyberScapeReact && typeof window.CyberScapeReact.renderScanResult === "function" && qrRoot) {
      window.CyberScapeReact.renderScanResult(qrRoot, {
        state: "success",
        report: data,
        onScanAnother: () => clearExtractedDestination()
      });
    }
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === "AbortError";
    const displayMsg = isTimeout
      ? "Inspection timed out after 20 seconds: The destination host or threat feeds took too long to reply. Please check your network connection and retry."
      : (err.message || "An unexpected error occurred during verification.");

    if (window.CyberScapeReact && typeof window.CyberScapeReact.renderScanResult === "function" && qrRoot) {
      window.CyberScapeReact.renderScanResult(qrRoot, {
        state: "error",
        error: displayMsg,
        url: url,
        onRetry: () => autoInspectQr(url),
        onScanAnother: () => clearExtractedDestination()
      });
    }
  } finally {
    if (analyzeBtn) analyzeBtn.disabled = false;
  }
}

/**
 * Initialize Event Listeners
 */
document.addEventListener("DOMContentLoaded", () => {
  enumerateCameras();

  // File Input Change
  if (fileInput) {
    fileInput.addEventListener("change", () => {
      if (fileInput.files && fileInput.files[0]) {
        handleQrImageFile(fileInput.files[0]);
      }
    });
  }

  // Drag & Drop
  if (dropZone) {
    ["dragenter", "dragover"].forEach(ev => {
      dropZone.addEventListener(ev, e => {
        e.preventDefault();
        dropZone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach(ev => {
      dropZone.addEventListener(ev, e => {
        e.preventDefault();
        dropZone.classList.remove("dragover");
      });
    });
    dropZone.addEventListener("drop", e => {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleQrImageFile(e.dataTransfer.files[0]);
      }
    });
  }

  // Check Destination Primary Action Button
  if (analyzeBtn) {
    analyzeBtn.addEventListener("click", () => {
      autoInspectQr(extractedUrl);
    });
  }
});

// Clean up camera on page unload or navigation
window.addEventListener("beforeunload", () => {
  stopCamera();
});
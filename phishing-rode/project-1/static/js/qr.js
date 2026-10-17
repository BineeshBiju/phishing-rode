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
    tabCamera.classList.add("active");
    tabUpload.classList.remove("active");
    modeCameraPanel.style.display = "block";
    modeUploadPanel.style.display = "none";
  } else {
    tabCamera.classList.remove("active");
    tabUpload.classList.add("active");
    modeCameraPanel.style.display = "none";
    modeUploadPanel.style.display = "block";
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

    // Update Toggle Button UI
    cameraToggleBtn.classList.add("camera-active");
    cameraToggleIcon.textContent = "⏹";
    cameraToggleText.textContent = "Stop Camera";
    setCameraStatus("Live webcam active. Align QR code inside reticle frame...", "success");

    // Re-enumerate to get device names once permission is granted
    enumerateCameras();

    // Begin scanning loop
    requestAnimationFrame(scanVideoFrame);
  } catch (err) {
    console.error("Camera startup error:", err);
    stopCamera();
    let msg = "Could not activate camera. Please ensure permissions are granted.";
    if (err.name === "NotAllowedError" || err.name === "PermissionDeniedError") {
      msg = "Camera permission denied. Please allow camera access in browser settings.";
    } else if (err.name === "NotFoundError" || err.name === "DevicesNotFoundError") {
      msg = "No camera hardware detected on this device. Use 'Upload Image' tab.";
    } else if (err.message) {
      msg = err.message;
    }
    setCameraStatus(msg, "error");
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
    cameraToggleIcon.textContent = "▶";
    cameraToggleText.textContent = "Start Camera";
  }
}

/**
 * Toggle Start / Stop Camera
 */
function toggleCamera() {
  if (isScanning) {
    stopCamera();
    setCameraStatus("Camera stopped. Ready to scan.", "normal");
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

      // Auto-Detect Trigger
      if (detectedCode) {
        playBeepTone();
        stopCamera();
        setExtractedUrl(detectedCode);
        setCameraStatus(`✅ QR Code detected: ${detectedCode.slice(0, 40)}...`, "success");
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
  if (destInput) destInput.focus();
}

/**
 * Helper to update camera status text
 */
function setCameraStatus(msg, type = "normal") {
  if (!cameraStatusEl) return;
  cameraStatusEl.className = "demo-note camera-status-bar" + 
    (type === "error" ? " note-error" : (type === "success" ? " note-success" : ""));
  cameraStatusEl.innerHTML = `<span>${escapeHtml(msg)}</span>`;
}

/**
 * Helper to update file upload status text
 */
function setUploadStatus(msg, type = "normal") {
  if (!uploadStatusEl) return;
  uploadStatusEl.className = "demo-note" + 
    (type === "error" ? " note-error" : (type === "success" ? " note-success" : ""));
  uploadStatusEl.textContent = msg;
}

/**
 * Handle File Upload (Drag & Drop or File Picker)
 */
async function handleQrImageFile(file) {
  if (!file) return;
  setUploadStatus(`Reading "${file.name}" (${(file.size / 1024).toFixed(1)} KB)...`);
  setExtractedUrl("");
  if (outEl) outEl.className = "result hidden";

  // Engine 1: Client-side jsQR decode via Object URL
  const objectUrl = URL.createObjectURL(file);
  const img = new Image();

  img.onload = async () => {
    let clientDecoded = null;
    try {
      const c = document.createElement("canvas");
      const ctx = c.getContext("2d", { willReadFrequently: true });
      c.width = img.naturalWidth;
      c.height = img.naturalHeight;
      ctx.drawImage(img, 0, 0);
      const imgData = ctx.getImageData(0, 0, c.width, c.height);

      // Try BarcodeDetector
      if ("BarcodeDetector" in window) {
        try {
          const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
          const barcodes = await detector.detect(c);
          if (barcodes.length > 0 && barcodes[0].rawValue) {
            clientDecoded = barcodes[0].rawValue.trim();
          }
        } catch (e) {}
      }

      // Try jsQR
      if (!clientDecoded && window.jsQR) {
        const code = window.jsQR(imgData.data, c.width, c.height, { inversionAttempts: "attemptBoth" });
        if (code && code.data) {
          clientDecoded = code.data.trim();
        }
      }
    } catch (e) {
      console.warn("Client-side image QR decode error:", e);
    } finally {
      URL.revokeObjectURL(objectUrl);
    }

    if (clientDecoded) {
      playBeepTone();
      setExtractedUrl(clientDecoded);
      setUploadStatus(`Decoded successfully: "${file.name}"`, "success");
      return;
    }

    // Engine 2: Server-side Python sandbox decoder (OpenCV fallback)
    try {
      setUploadStatus("Processing with server-side forensic decoder...");
      const formData = new FormData();
      formData.append("qr_file", file);
      const resp = await fetch("/api/decode-qr", {
        method: "POST",
        body: formData
      });
      const data = await resp.json();
      if (resp.ok && data.success && data.data) {
        playBeepTone();
        setExtractedUrl(data.data.trim());
        setUploadStatus(`Decoded successfully via Server Engine (${data.engine || "OpenCV"}).`, "success");
      } else {
        setUploadStatus(data.error || "No readable QR code found in the image. Please verify resolution.", "error");
      }
    } catch (err) {
      setUploadStatus("Failed to process QR image: " + err.message, "error");
    }
  };

  img.onerror = () => {
    URL.revokeObjectURL(objectUrl);
    setUploadStatus("The selected file is not a valid image format.", "error");
  };

  img.src = objectUrl;
}

/**
 * Load Sample QR Test (One-click demonstration)
 */
function loadSampleQrTest() {
  playBeepTone();
  setExtractedUrl("https://example.com/qr-destination");
  setCameraStatus("Sample QR destination loaded for testing.", "success");
  if (currentMode === "upload") {
    setUploadStatus("Loaded sample: https://example.com/qr-destination", "success");
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
    analyzeBtn.addEventListener("click", async () => {
      if (!extractedUrl) return;

      // Intercept unauthenticated users
      if (window.CYBER_AUTH && !window.CYBER_AUTH.isAuthenticated) {
        openAuthModal();
        return;
      }

      analyzeBtn.disabled = true;
      if (outEl) {
        outEl.className = "result";
        outEl.innerHTML = '<div class="loading-state"><span class="pulse-indicator"></span> Running deep threat inspection & redirect tracing on QR destination...</div>';
      }

      try {
        const res = await fetch("/api/qr-result", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: extractedUrl })
        });
        const data = await res.json();
        analyzeBtn.disabled = false;
        if (res.ok && outEl) {
          renderResult(data, outEl);
        } else if (outEl) {
          outEl.className = "result malicious";
          outEl.textContent = data.error || "Analysis failed.";
        }
      } catch (err) {
        analyzeBtn.disabled = false;
        if (outEl) {
          outEl.className = "result malicious";
          outEl.textContent = "Inspection error: " + err.message;
        }
      }
    });
  }
});

// Clean up camera on page unload or navigation
window.addEventListener("beforeunload", () => {
  stopCamera();
});
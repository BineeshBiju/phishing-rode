/*
 * Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
 * See LICENSE for details.
 */
/**
 * CyberScape Enhanced URL Threat Scanner Controller
 * Production-grade frontend with async/await, AbortController timeouts,
 * progressive loading states, and robust error handling.
 */

async function executeUrlScan(targetUrl) {
  const url = (targetUrl || "").trim();
  const el = document.getElementById("scanResult");
  const checkBtn = document.getElementById("checkBtn");
  const urlInput = document.getElementById("urlInput");

  if (!el || !checkBtn) return;

  if (!url) {
    el.className = "result malicious";
    el.innerHTML = `
      <div class="result-card-container">
        <div class="factors-safe" style="color:var(--status-malicious-text)">
          <span class="badge-tag-danger font-mono" style="margin-right:6px;font-size:0.75rem;padding:2px 6px;border-radius:4px;background:rgba(239,68,68,0.2);">INPUT REQUIRED</span><b>Error:</b> Please enter a valid HTTP or HTTPS destination URL to analyze.
        </div>
      </div>
    `;
    return;
  }

  // Basic client-side protocol check
  if (!/^https?:\/\//i.test(url)) {
    el.className = "result malicious";
    el.innerHTML = `
      <div class="result-card-container">
        <div class="factors-safe" style="color:var(--status-malicious-text)">
          <span class="badge-tag-danger font-mono" style="margin-right:6px;font-size:0.75rem;padding:2px 6px;border-radius:4px;background:rgba(239,68,68,0.2);">INVALID PROTOCOL</span><b>Error:</b> Only standard web links (<code>http://</code> or <code>https://</code>) are supported.
        </div>
      </div>
    `;
    return;
  }

  // Intercept unauthenticated users
  if (window.CYBER_AUTH && !window.CYBER_AUTH.isAuthenticated) {
    window.location.href = (window.CYBER_AUTH && window.CYBER_AUTH.loginUrl) || "/login";
    return;
  }

  const originalBtnText = checkBtn.innerHTML;
  checkBtn.disabled = true;
  checkBtn.innerHTML = '<span class="pulse-indicator"></span> Analyzing Link...';

  el.className = "result";
  el.innerHTML = `
    <div class="result-card-container">
      <div class="loading-state">
        <div class="loading-header">
          <span class="pulse-indicator"></span>
          <b>Executing Multi-Layer Cybersecurity Threat Inspection...</b>
        </div>
        <ul class="loading-steps font-mono">
          <li class="step-active">1/4. Querying live URLhaus & threat intelligence databases...</li>
          <li>2/4. Safely sandbox-tracing HTTP redirect pathways...</li>
          <li>3/4. Running AI Random Forest Phishing Domain Classifier...</li>
          <li>4/4. Resolving DNS and real-time server Geo-IP telemetry...</li>
        </ul>
      </div>
    </div>
  `;

  // 15-second AbortController timeout handling
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const res = await fetch("/check-url", {
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
      let errMsg = "Inspection request failed.";
      try {
        const errJson = await res.json();
        errMsg = errJson.error || errMsg;
      } catch (e) {}
      throw new Error(errMsg);
    }

    const data = await res.json();
    renderResult(data, el);

    // Smoothly scroll result into view if on mobile/smaller screens
    if (window.innerWidth < 768 && el.scrollIntoView) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (err) {
    clearTimeout(timeoutId);
    el.className = "result malicious";

    const isTimeout = err.name === "AbortError";
    const displayMsg = isTimeout
      ? "Inspection timed out: The live threat intelligence network took longer than 15 seconds to reply. Please check your connection and try again."
      : err.message || "An unexpected error occurred during threat scanning.";

    el.innerHTML = `
      <div class="result-card-container">
        <div class="factors-safe" style="color:var(--status-malicious-text)">
          <div style="font-size:1.1rem; font-weight:700; margin-bottom:6px; display:flex; align-items:center; gap:8px;">
            <span class="badge-tag-danger font-mono" style="font-size:0.75rem; padding:2px 6px; border-radius:4px; background:rgba(239,68,68,0.2);">${isTimeout ? "TIMEOUT" : "ERROR"}</span>
            <span>${isTimeout ? "Request Timeout" : "Inspection Error"}</span>
          </div>
          <div>${escapeHtml(displayMsg)}</div>
        </div>
      </div>
    `;
  } finally {
    checkBtn.disabled = false;
    checkBtn.innerHTML = originalBtnText;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const checkBtn = document.getElementById("checkBtn");
  const urlInput = document.getElementById("urlInput");

  if (checkBtn && urlInput) {
    checkBtn.addEventListener("click", () => {
      executeUrlScan(urlInput.value);
    });

    urlInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        executeUrlScan(urlInput.value);
      }
    });
  }

  // Check for auto-scan queries passed via sessionStorage
  try {
    const pending = sessionStorage.getItem("pendingScanUrl");
    if (pending) {
      sessionStorage.removeItem("pendingScanUrl");
      if (urlInput) {
        urlInput.value = pending;
        setTimeout(() => {
          executeUrlScan(pending);
        }, 150);
      }
    }
  } catch (e) {}
});

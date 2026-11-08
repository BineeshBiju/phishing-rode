document.getElementById("checkBtn").addEventListener("click", async () => {
  const urlInput = document.getElementById("urlInput");
  const checkBtn = document.getElementById("checkBtn");
  const url = (urlInput.value || "").trim();
  const el = document.getElementById("scanResult");

  if (!url) {
    el.className = "result malicious";
    el.innerHTML = '<div class="factors-safe" style="color:var(--status-malicious-text)">⚠️ Please enter a valid URL to analyze.</div>';
    return;
  }

  // Intercept unauthenticated users
  if (window.CYBER_AUTH && !window.CYBER_AUTH.isAuthenticated) {
    openAuthModal();
    return;
  }

  const originalBtnText = checkBtn.innerHTML;
  checkBtn.disabled = true;
  checkBtn.innerHTML = '<span class="pulse-indicator"></span> Analyzing Link...';
  el.className = "result";
  el.innerHTML = '<div class="loading-state"><span class="pulse-indicator"></span> Running multi-layer AI inspection, Threat Intelligence feeds, and Geo-IP resolution...</div>';

  try {
    const res = await fetch("/api/check-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan failed");
    renderResult(data, el);
  } catch (e) {
    el.className = "result malicious";
    el.innerHTML = `<div class="factors-safe" style="color:var(--status-malicious-text)">❌ Inspection Error: ${escapeHtml(e.message)}</div>`;
  } finally {
    checkBtn.disabled = false;
    checkBtn.innerHTML = originalBtnText;
  }
});

document.getElementById("urlInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    document.getElementById("checkBtn").click();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  try {
    const pending = sessionStorage.getItem("pendingScanUrl");
    if (pending) {
      sessionStorage.removeItem("pendingScanUrl");
      const input = document.getElementById("urlInput");
      if (input) {
        input.value = pending;
        setTimeout(() => {
          document.getElementById("checkBtn").click();
        }, 150);
      }
    }
  } catch (e) {}
});
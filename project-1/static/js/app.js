/*
 * Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
 * See LICENSE for details.
 */
function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, m => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[m]));
}

async function copyReportJson(data) {
  try {
    const jsonStr = typeof data === "string" ? data : JSON.stringify(data, null, 2);
    await navigator.clipboard.writeText(jsonStr);
    const btn = document.getElementById("copyJsonBtn");
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = '<span>Copied!</span>';
      setTimeout(() => { btn.innerHTML = orig; }, 1800);
    }
  } catch (err) {
    alert("Could not copy JSON to clipboard: " + err.message);
  }
}

async function downloadForensicReport(url) {
  const btn = document.getElementById("downloadPdfBtn");
  const originalHtml = btn ? btn.innerHTML : 'Download PDF Forensic Report';
  if (btn) {
    btn.innerHTML = 'Generating PDF...';
    btn.disabled = true;
    if (window.lucide && typeof window.lucide.createIcons === "function") lucide.createIcons();
  }

  try {
    let payload = { url: (url || "").trim() };
    try {
      const cachedStr = sessionStorage.getItem("guardResult");
      if (cachedStr) {
        const cached = JSON.parse(cachedStr);
        if (cached && (!url || cached.url === url)) {
          payload = cached;
        }
      }
    } catch (e) {}

    if (!payload.url && url) {
      payload.url = url;
    }

    const res = await fetch("/generate-report", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Accept": "application/pdf, application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      let errMsg = "Failed to generate PDF forensic report";
      try {
        const errData = await res.json();
        errMsg = errData.error || errMsg;
      } catch (e) {}
      throw new Error(errMsg);
    }

    const blob = await res.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = downloadUrl;
    const target = (payload.url || url || "target").replace(/^https?:\/\//i, "").split("/")[0].replace(/[^a-zA-Z0-9_-]/g, "_");
    a.download = `CyberScape_Forensic_Report_${target || "scan"}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(downloadUrl);
  } catch (err) {
    alert("Error downloading PDF report: " + err.message);
  } finally {
    if (btn) {
      btn.innerHTML = originalHtml;
      btn.disabled = false;
    }
  }
}

function deriveVerdict(score, status) {
  if (status === "MALICIOUS" || score >= 75) {
    return {
      text: "High risk, do not open",
      level: "High Risk",
      colorClass: "text-dangerSoft",
      badgeClass: "bg-danger text-ground"
    };
  }
  if (status === "SUSPICIOUS" || score >= 40) {
    return {
      text: "Elevated risk, proceed with caution",
      level: "Elevated Risk",
      colorClass: "text-amber-400",
      badgeClass: "bg-amber-500 text-ground"
    };
  }
  return {
    text: "Low risk, verified safe",
    level: "Low Risk",
    colorClass: "text-safe",
    badgeClass: "bg-safe text-ground"
  };
}

function renderResult(r, el) {
  if (!el || !r) return;

  if (window.CyberScapeReact && typeof window.CyberScapeReact.renderScanResult === "function") {
    window.CyberScapeReact.renderScanResult(el, {
      state: "success",
      report: r,
      onScanAnother: () => {
        if (typeof window.clearExtractedDestination === "function") {
          window.clearExtractedDestination();
        }
        window.CyberScapeReact.renderScanResult(el, { state: "idle" });
      }
    });
    return;
  }

  const score = r.score !== undefined ? Number(r.score) : (r.status === "MALICIOUS" ? 85 : 5);
  const confidence = r.confidence !== undefined ? r.confidence : (r.ml_analysis && r.ml_analysis.confidence ? r.ml_analysis.confidence : 92);
  const verdict = deriveVerdict(score, r.status);

  // Build hops list
  const redirect = r.redirect_chain || {};
  const chain = redirect.chain || [];
  let hopsHtml = "";

  if (chain.length > 0) {
    hopsHtml = chain.map((h, i) => {
      const isLast = i === chain.length - 1;
      const num = String(i + 1).padStart(2, "0");
      const hopUrl = escapeHtml(h.url || r.url);
      const hopDomain = escapeHtml(h.domain || "");
      const statusCode = h.status_code || 200;
      const desc = `HTTP ${statusCode} -> ${escapeHtml(h.reason || (isLast ? "Terminal Destination" : "Redirect Hop"))}${hopDomain ? ` [${hopDomain}]` : ""}`;
      const isDangerous = (isLast && r.status === "MALICIOUS") || h.status_code >= 400;
      const urlClass = isDangerous ? "text-dangerSoft font-bold" : "text-ground";
      return `
        <div class="py-3.5 first:pt-0 last:pb-0 flex items-start gap-4">
          <span class="font-mono text-xs text-muted font-bold shrink-0 pt-0.5">${num}</span>
          <div class="flex-grow min-w-0">
            <div class="font-mono text-sm font-medium break-all ${urlClass}">${hopUrl}</div>
            <div class="text-xs text-line/70 mt-0.5 leading-relaxed font-mono">${desc}</div>
          </div>
        </div>
      `;
    }).join("");
  } else {
    const geo = r.geo_ip || {};
    hopsHtml = `
      <div class="py-3.5 first:pt-0 flex items-start gap-4">
        <span class="font-mono text-xs text-muted font-bold shrink-0 pt-0.5">01</span>
        <div class="flex-grow min-w-0">
          <div class="font-mono text-sm font-medium break-all text-ground">${escapeHtml(r.url)}</div>
          <div class="text-xs text-line/70 mt-0.5 leading-relaxed font-mono">Direct Destination -> Host: ${escapeHtml(r.domain || geo.hostname || "Direct Host")}, Geo-IP: ${escapeHtml(geo.country || "Verified")}</div>
        </div>
      </div>
    `;
    if (r.final_url && r.final_url !== r.url) {
      hopsHtml += `
        <div class="py-3.5 last:pb-0 flex items-start gap-4">
          <span class="font-mono text-xs text-muted font-bold shrink-0 pt-0.5">02</span>
          <div class="flex-grow min-w-0">
            <div class="font-mono text-sm font-medium break-all ${r.status === 'MALICIOUS' ? 'text-dangerSoft font-bold' : 'text-ground'}">${escapeHtml(r.final_url)}</div>
            <div class="text-xs text-line/70 mt-0.5 leading-relaxed font-mono">Final Resolved Sandbox Endpoint -> Status: ${escapeHtml(r.status)}</div>
          </div>
        </div>
      `;
    }
  }

  const hopCount = chain.length > 0 ? chain.length : (r.final_url && r.final_url !== r.url ? 2 : 1);

  // Build signals list
  const signals = r.signals || [];
  let signalsHtml = "";
  if (signals.length > 0) {
    signalsHtml = signals.map(sig => {
      const sev = (sig.severity || "info").toLowerCase();
      let badgeStyle = "bg-line/20 text-line border-line/40";
      if (sev === "critical" || sev === "high" || sev === "danger") {
        badgeStyle = "bg-danger/20 text-dangerSoft border-danger/40";
      } else if (sev === "warning" || sev === "suspicious") {
        badgeStyle = "bg-amber-500/20 text-amber-300 border-amber-500/40";
      } else if (sev === "safe" || sev === "low") {
        badgeStyle = "bg-safe/20 text-emerald-300 border-safe/40";
      }
      return `
        <div class="py-2.5 flex items-start justify-between gap-3 text-xs border-b border-inkLine/40 last:border-b-0">
          <div class="flex flex-col min-w-0">
            <div class="flex items-center gap-2 mb-1">
              <span class="font-mono font-bold px-1.5 py-0.5 rounded text-[10px] uppercase border ${badgeStyle}">${escapeHtml(sig.severity || "INFO")}</span>
              <span class="font-semibold text-ground/90">${escapeHtml(sig.source || "Detector")}</span>
            </div>
            <p class="text-line/80 leading-relaxed">${escapeHtml(sig.evidence || sig.description || "")}</p>
          </div>
        </div>
      `;
    }).join("");
  } else if (r.reasons && r.reasons.length > 0) {
    signalsHtml = r.reasons.map(reason => `
      <div class="py-2 flex items-start gap-2 text-xs border-b border-inkLine/40 last:border-b-0 text-line/80">
        <span class="text-line font-mono">&bull;</span>
        <span class="leading-relaxed">${escapeHtml(reason)}</span>
      </div>
    `).join("");
  } else {
    signalsHtml = `
      <div class="py-2 text-xs text-line/60">No anomaly or threat indicators detected during scan.</div>
    `;
  }

  // Build sources status list
  const threatIntel = r.threat_intel || {};
  const sources = [
    {
      name: "URLhaus Feed",
      status: threatIntel.urlhaus?.status === "MALICIOUS" ? "FLAGGED" : (threatIntel.urlhaus?.status === "UNAVAILABLE" ? "UNAVAILABLE" : "OK")
    },
    {
      name: "VirusTotal",
      status: threatIntel.virustotal?.status === "MALICIOUS" ? "FLAGGED" : (threatIntel.virustotal?.status === "STANDBY" || threatIntel.virustotal?.status === "SAFE" ? "OK" : (threatIntel.virustotal?.status || "OK"))
    },
    {
      name: "Safe Browsing",
      status: threatIntel.safebrowsing?.status === "MALICIOUS" ? "FLAGGED" : (threatIntel.safebrowsing?.status === "SAFE" ? "OK" : (threatIntel.safebrowsing?.status || "OK"))
    },
    {
      name: "DNS & Geo-IP",
      status: (r.geo_ip && r.geo_ip.status !== "error") ? "OK" : "UNAVAILABLE"
    }
  ];

  const sourcesHtml = sources.map(s => {
    let color = "text-emerald-400";
    if (s.status === "FLAGGED") color = "text-dangerSoft font-bold";
    else if (s.status === "UNAVAILABLE") color = "text-muted";
    return `
      <div class="flex items-center gap-1.5 px-2.5 py-1 rounded bg-inkSoft border border-inkLine text-[11px] font-mono">
        <span class="w-1.5 h-1.5 rounded-full ${s.status === 'FLAGGED' ? 'bg-dangerSoft' : (s.status === 'UNAVAILABLE' ? 'bg-muted' : 'bg-emerald-400')}"></span>
        <span class="text-line">${escapeHtml(s.name)}:</span>
        <span class="${color}">${escapeHtml(s.status)}</span>
      </div>
    `;
  }).join("");

  el.className = "w-full";
  el.innerHTML = `
    <div class="bg-ink rounded-panelLg p-6 sm:p-8 text-ground flex flex-col justify-between min-h-[460px] shadow-sm">
      <div>
        <!-- Top header: Mode/Type + Hop Count -->
        <div class="flex items-center justify-between border-b border-inkLine pb-4 mb-5">
          <span class="text-sm font-medium text-line tracking-wide">Inspection Result</span>
          <span class="font-mono text-sm text-line tracking-wider">${hopCount} hop${hopCount === 1 ? '' : 's'}</span>
        </div>

        <!-- Hops List -->
        <div class="flex flex-col divide-y divide-inkLine mb-6">
          ${hopsHtml}
        </div>

        <!-- Sources Checked Row -->
        <div class="mb-6 pt-4 border-t border-inkLine">
          <span class="block text-[11px] uppercase tracking-wider text-line/60 font-semibold mb-2 font-mono">Sources Checked</span>
          <div class="flex flex-wrap gap-2">
            ${sourcesHtml}
          </div>
        </div>

        <!-- Why this score? / Signals List -->
        <div class="mb-6 pt-4 border-t border-inkLine">
          <div class="flex items-center justify-between mb-2">
            <span class="text-[11px] uppercase tracking-wider text-line/60 font-semibold font-mono">Why this score? / Signals</span>
            <span class="text-[11px] font-mono text-line/60">${signals.length || (r.reasons ? r.reasons.length : 0)} indicator(s)</span>
          </div>
          <div class="flex flex-col bg-inkSoft/40 rounded-input p-3 border border-inkLine/60">
            ${signalsHtml}
          </div>
        </div>
      </div>

      <!-- Bottom Verdict & Score Bar -->
      <div class="mt-4 pt-4 border-t border-inkLine/60">
        <div class="bg-inkSoft rounded-[8px] px-5 py-4 flex items-center justify-between gap-4">
          <div class="flex flex-col">
            <span class="text-xs uppercase tracking-wider text-line/60 font-semibold">Security Verdict</span>
            <span class="text-[19px] sm:text-[22px] font-bold ${verdict.colorClass} leading-tight">${verdict.text}</span>
            <span class="text-[11px] font-mono text-line/60 mt-1">${confidence}% Confidence Assessment</span>
          </div>
          <div class="text-right shrink-0">
            <span class="block text-xs uppercase tracking-wider text-line/60 font-semibold">Risk Score</span>
            <span class="font-mono text-[28px] sm:text-[34px] font-bold text-ground leading-none">${score}/100</span>
          </div>
        </div>

        <div class="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
          <button type="button" id="downloadPdfBtn" onclick="downloadForensicReport('${escapeHtml(r.url)}')"
            class="py-2.5 px-4 bg-ground text-ink rounded-btn text-xs font-semibold hover:bg-panel transition-colors cursor-pointer text-center">
            Download PDF Forensic Report
          </button>
          <button type="button" id="copyJsonBtn" onclick='copyReportJson(${JSON.stringify(JSON.stringify(r))})'
            class="py-2.5 px-4 bg-inkSoft border border-inkLine text-ground rounded-btn text-xs font-semibold hover:bg-inkLine transition-colors cursor-pointer text-center">
            Copy JSON
          </button>
        </div>
      </div>
    </div>
  `;

  try {
    sessionStorage.setItem("guardResult", JSON.stringify(r));
  } catch (e) {}

  if (window.lucide && typeof window.lucide.createIcons === "function") {
    lucide.createIcons();
  }
}

// Window exports
window.renderResult = renderResult;
window.downloadForensicReport = downloadForensicReport;
window.copyReportJson = copyReportJson;

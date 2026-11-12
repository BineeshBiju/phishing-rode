/*
 * Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
 * See LICENSE for details.
 */
/**
 * CyberScape Email Analyzer Frontend Application
 * Handles raw RFC 822 header validation, sender spoofing detection,
 * SPF/DKIM/DMARC inspection, originating IP geo-telemetry, hop timeline,
 * attachment forensics, and NLP phishing intent analysis.
 * Strict token compliance: ground (#E8EAE4), panel (#F6F7F3), ink (#12161D), line (#C9CDC4),
 * danger (#C23A0C), safe (#1D6B4C), suspicious (#8A5A00). Zero emojis.
 */

(function () {
  let currentEmailAnalysis = null;

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  window.copyText = function (text, btnElement) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        if (btnElement) {
          const orig = btnElement.innerText;
          btnElement.innerText = "Copied";
          setTimeout(() => {
            btnElement.innerText = orig;
          }, 1800);
        }
      });
    }
  };

  window.switchEmailMode = function (mode) {
    const tabPaste = document.getElementById("tabEmailPaste");
    const tabUpload = document.getElementById("tabEmailUpload");
    const modePaste = document.getElementById("modeEmailPaste");
    const modeUpload = document.getElementById("modeEmailUpload");

    if (mode === "upload") {
      if (modePaste) modePaste.style.display = "none";
      if (modeUpload) modeUpload.style.display = "flex";

      if (tabUpload) {
        tabUpload.className = "px-4 py-1.5 rounded-chip text-sm font-semibold transition-colors bg-ink text-ground cursor-pointer";
      }
      if (tabPaste) {
        tabPaste.className = "px-4 py-1.5 rounded-chip text-sm font-medium transition-colors text-muted hover:text-ink cursor-pointer";
      }
    } else {
      if (modeUpload) modeUpload.style.display = "none";
      if (modePaste) modePaste.style.display = "flex";

      if (tabPaste) {
        tabPaste.className = "px-4 py-1.5 rounded-chip text-sm font-semibold transition-colors bg-ink text-ground cursor-pointer";
      }
      if (tabUpload) {
        tabUpload.className = "px-4 py-1.5 rounded-chip text-sm font-medium transition-colors text-muted hover:text-ink cursor-pointer";
      }
    }
  };

  window.clearInputs = function () {
    const headerInput = document.getElementById("headerInput");
    const contentInput = document.getElementById("contentInput");
    const emlFile = document.getElementById("emlFile");
    const emlUploadStatus = document.getElementById("emlUploadStatus");
    const resultEl = document.getElementById("emailScanResult");

    if (headerInput) headerInput.value = "";
    if (contentInput) contentInput.value = "";
    if (emlFile) emlFile.value = "";
    if (emlUploadStatus) emlUploadStatus.innerText = "No file selected.";
    if (resultEl) resultEl.innerHTML = "";
    currentEmailAnalysis = null;
  };

  window.downloadEmailReport = async function () {
    if (!currentEmailAnalysis) {
      alert("Please analyze an email first.");
      return;
    }
    const btn = document.getElementById("emailReportBtn");
    const origHtml = btn ? btn.innerHTML : "Download PDF Report";
    if (btn) {
      btn.innerHTML = "Generating PDF...";
      btn.disabled = true;
    }

    try {
      const res = await fetch("/generate-email-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(currentEmailAnalysis)
      });
      if (!res.ok) throw new Error("Failed to generate PDF forensic report.");

      const blob = await res.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = downloadUrl;
      a.download = `CyberScape_Email_Forensic_Report_${Date.now()}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      alert("Could not generate report: " + err.message);
    } finally {
      if (btn) {
        btn.innerHTML = origHtml;
        btn.disabled = false;
      }
    }
  };

  window.copyEmailAnalysisJson = function () {
    if (!currentEmailAnalysis) return;
    const text = JSON.stringify(currentEmailAnalysis, null, 2);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
      const btn = document.getElementById("emailCopyJsonBtn");
      if (btn) {
        const orig = btn.innerText;
        btn.innerText = "Copied JSON";
        setTimeout(() => {
          btn.innerText = orig;
        }, 2000);
      }
    }
  };

  function renderEmailResult(data, el) {
    currentEmailAnalysis = data;
    const rawVerdict = (data.verdict || "UNKNOWN").toUpperCase();
    const isMalicious = rawVerdict === "MALICIOUS" || rawVerdict === "PHISHING" || data.score >= 70;
    const isSuspicious = !isMalicious && (rawVerdict === "SUSPICIOUS" || data.score >= 30);
    const isSafe = !isMalicious && !isSuspicious;

    const score = data.score !== undefined ? data.score : 0;
    const sender = data.sender_check || data.header_analysis || {};
    const auth = data.auth_results || (data.header_analysis && data.header_analysis.authentication) || {};
    const origin = data.origin_ip || (data.header_analysis && data.header_analysis.geo_ip) || {};
    const findings = data.findings || [];
    const links = data.links || (data.content_findings && data.content_findings.extracted_urls) || [];
    const attachments = data.attachments || [];
    const hops = data.hop_timeline || (data.header_analysis && data.header_analysis.hop_timeline) || [];
    const alignment = data.alignment || (data.auth_results && data.auth_results.alignment) || {};
    const recs = data.recommendations || [];

    // Verdict styling
    let verdictColorClass = "text-safe";
    let verdictBadgeClass = "border border-safe text-safe bg-safe/5";
    let verdictLabel = "Low risk, authenticated email";
    let verdictDesc = "Email headers validly align with sending servers and pass cryptographic checks.";

    if (isMalicious) {
      verdictColorClass = "text-danger";
      verdictBadgeClass = "border border-danger text-danger bg-danger/5";
      verdictLabel = "High risk, spoofed fake email";
      verdictDesc = "Confirmed sender identity spoofing, critical authentication failure, dangerous attachment, or deceptive phishing lure detected.";
    } else if (isSuspicious) {
      verdictColorClass = "text-suspicious";
      verdictBadgeClass = "border border-suspicious text-suspicious bg-suspicious/5";
      verdictLabel = "Suspicious, proceed with caution";
      verdictDesc = "Anomalous reply routing, unverified sending domain, or elevated urgency language identified.";
    }

    const spfStatus = (auth.spf && auth.spf.status ? auth.spf.status : (auth.spf || "NONE")).toUpperCase();
    const dkimStatus = (auth.dkim && auth.dkim.status ? auth.dkim.status : (auth.dkim || "NONE")).toUpperCase();
    const dmarcStatus = (auth.dmarc && auth.dmarc.status ? auth.dmarc.status : (auth.dmarc || "NONE")).toUpperCase();

    const getAuthBadge = (st) => {
      st = (st || "").toUpperCase();
      if (st === "PASS") return "border-safe text-safe bg-safe/5";
      if (st === "FAIL") return "border-danger text-danger bg-danger/5";
      if (st === "SOFTFAIL") return "border-suspicious text-suspicious bg-suspicious/5";
      return "border-line text-muted bg-ground";
    };

    const getSevBadge = (sev) => {
      sev = (sev || "low").toLowerCase();
      if (sev === "critical" || sev === "high") return "border-danger text-danger bg-danger/5";
      if (sev === "medium") return "border-suspicious text-suspicious bg-suspicious/5";
      if (sev === "safe") return "border-safe text-safe bg-safe/5";
      return "border-line text-muted bg-ground";
    };

    const getAlignBadge = (aligned) => {
      if (aligned === true) return '<span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-safe text-safe bg-safe/5">ALIGNED</span>';
      if (aligned === false) return '<span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-danger text-danger bg-danger/5">MISALIGNED</span>';
      return '<span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-line text-muted bg-ground">UNCHECKED</span>';
    };

    el.className = "w-full mt-10 scroll-mt-24";
    el.innerHTML = `
      <div class="bg-panel rounded-[12px] border border-line p-6 sm:p-8 w-full text-ink shadow-sm space-y-8">
        
        <!-- SECTION 1: VERDICT BANNER -->
        <div class="flex flex-col md:flex-row md:items-start justify-between gap-6 pb-6 border-b border-line">
          <div class="space-y-2">
            <div class="flex items-center gap-3 flex-wrap">
              <span class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">Email Forensics</span>
              <span class="text-[11px] font-mono font-bold px-2 py-0.5 rounded uppercase ${verdictBadgeClass}">
                ${isMalicious ? "PHISHING" : (isSuspicious ? "SUSPICIOUS" : "SAFE")}
              </span>
              ${data.attachment_count ? `
                <span class="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-ground text-ink border border-line">
                  ${data.attachment_count} Attachment${data.attachment_count > 1 ? "s" : ""}
                </span>
              ` : ""}
            </div>
            <h2 class="text-2xl sm:text-3xl font-bold ${verdictColorClass} tracking-tight">
              ${verdictLabel}
            </h2>
            <p class="text-sm text-muted max-w-[620px] leading-relaxed">
              ${verdictDesc}
            </p>
            <div class="pt-2 flex items-center gap-2 text-xs font-mono text-muted">
              <span class="text-ink font-semibold">Claimed Sender:</span>
              <span class="break-all">${escapeHtml(sender.from_name ? `${sender.from_name} <${sender.from_addr}>` : (sender.from_addr || "Not specified"))}</span>
            </div>
          </div>

          <!-- Score & Actions -->
          <div class="flex flex-col items-start md:items-end shrink-0 space-y-4">
            <div class="text-left md:text-right">
              <span class="block text-xs uppercase tracking-wider text-muted font-semibold">Threat Risk Score</span>
              <span class="font-mono text-4xl sm:text-5xl font-bold text-ink leading-none mt-1 block">
                ${score}/100
              </span>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              <button
                type="button"
                id="emailReportBtn"
                onclick="downloadEmailReport()"
                class="py-2.5 px-4 bg-ink text-ground rounded-btn text-xs font-semibold hover:bg-ink/90 transition-colors cursor-pointer text-center"
              >
                Download PDF Report
              </button>
              <button
                type="button"
                id="emailCopyJsonBtn"
                onclick="copyEmailAnalysisJson()"
                class="py-2.5 px-3.5 bg-panel border border-ink text-ink rounded-btn text-xs font-semibold hover:bg-ground transition-colors cursor-pointer text-center"
              >
                Copy JSON
              </button>
            </div>
          </div>
        </div>

        <!-- SECTION 2: SPF / DKIM / DMARC AUTHENTICATION & DNS ALIGNMENT -->
        <div class="space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">
              Cryptographic Authentication & DNS Verification
            </h3>
            <span class="text-xs font-mono text-muted">RFC 7208 / 6376 / 7489</span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <!-- SPF Card -->
            <div class="p-4 rounded-input border border-line bg-ground/40 space-y-2">
              <div class="flex items-center justify-between">
                <span class="font-mono text-xs font-bold text-ink">SPF Record</span>
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getAuthBadge(spfStatus)}">
                  ${spfStatus}
                </span>
              </div>
              <p class="text-xs text-muted leading-relaxed font-sans">
                ${escapeHtml(auth.spf && auth.spf.explanation ? auth.spf.explanation : "Sender Policy Framework validates sending server authorization.")}
              </p>
              ${auth.spf && auth.spf.dns_match !== undefined ? `
                <div class="pt-1 text-[11px] font-mono flex items-center gap-1.5 ${auth.spf.dns_match ? 'text-safe' : 'text-danger'}">
                  <span class="font-bold">[DNS]</span>
                  <span>${auth.spf.dns_match ? 'Sending IP authorized in SPF record' : 'Sending IP not authorized in SPF record'}</span>
                </div>
              ` : ''}
              ${auth.spf && auth.spf.spf_record ? `
                <div class="p-2 rounded bg-panel border border-line/60 font-mono text-[10px] text-muted break-all">
                  ${escapeHtml(auth.spf.spf_record)}
                </div>
              ` : ''}
            </div>

            <!-- DKIM Card -->
            <div class="p-4 rounded-input border border-line bg-ground/40 space-y-2">
              <div class="flex items-center justify-between">
                <span class="font-mono text-xs font-bold text-ink">DKIM Signature</span>
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getAuthBadge(dkimStatus)}">
                  ${dkimStatus}
                </span>
              </div>
              <p class="text-xs text-muted leading-relaxed font-sans">
                ${escapeHtml(auth.dkim && auth.dkim.explanation ? auth.dkim.explanation : "DomainKeys Identified Mail verifies cryptographic header integrity.")}
              </p>
              ${auth.dkim && auth.dkim.target ? `
                <div class="pt-1 text-[11px] font-mono text-muted break-all">
                  <span class="text-ink font-semibold">Selector Target:</span> ${escapeHtml(auth.dkim.target)}
                </div>
                <div class="text-[11px] font-mono flex items-center gap-1.5 ${auth.dkim.dns_key_found ? 'text-safe' : 'text-danger'}">
                  <span class="font-bold">[DNS]</span>
                  <span>${auth.dkim.dns_key_found ? 'Public key record published' : 'Public key record not found in DNS'}</span>
                </div>
              ` : ''}
            </div>

            <!-- DMARC Card -->
            <div class="p-4 rounded-input border border-line bg-ground/40 space-y-2">
              <div class="flex items-center justify-between">
                <span class="font-mono text-xs font-bold text-ink">DMARC Policy</span>
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getAuthBadge(dmarcStatus)}">
                  ${dmarcStatus}
                </span>
              </div>
              <p class="text-xs text-muted leading-relaxed font-sans">
                ${escapeHtml(auth.dmarc && auth.dmarc.explanation ? auth.dmarc.explanation : "Domain-based Message Authentication enforces domain policy conformance.")}
              </p>
            </div>
          </div>

          <!-- Protocol Alignment Details -->
          <div class="p-3.5 rounded-input border border-line bg-ground/25 text-xs font-sans space-y-2">
            <div class="text-[11px] font-mono uppercase tracking-wider text-muted font-bold">Domain Identifier Alignment</div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="flex items-center justify-between p-2 rounded bg-panel border border-line/60">
                <span class="text-muted font-mono">SPF Alignment (From vs Return-Path):</span>
                <span class="ml-2">${getAlignBadge(alignment.spf_aligned)}</span>
              </div>
              <div class="flex items-center justify-between p-2 rounded bg-panel border border-line/60">
                <span class="text-muted font-mono">DKIM Alignment (From vs d=):</span>
                <span class="ml-2">${getAlignBadge(alignment.dkim_aligned)}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- SECTION 3: RECEIVED CHAIN HOP TIMELINE -->
        ${hops.length > 0 ? `
          <div class="space-y-4 pt-6 border-t border-line">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">
                  Received Chain Hop Timeline (${hops.length} Hops)
                </h3>
                <p class="text-xs text-muted mt-0.5">Chronological relay path from originating sender to final recipient mail server</p>
              </div>
              <span class="text-xs font-mono text-muted">Bottom-Up Chronology</span>
            </div>

            <div class="space-y-3 font-sans">
              ${hops.map((hop, idx) => `
                <div class="p-3.5 rounded-input border ${hop.is_origin ? 'border-danger/60 bg-danger/5' : 'border-line bg-panel'} text-xs space-y-2 transition-colors">
                  <div class="flex items-center justify-between gap-2 flex-wrap">
                    <div class="flex items-center gap-2">
                      <span class="font-mono font-bold text-xs ${hop.is_origin ? 'text-danger' : 'text-ink'}">
                        HOP ${String(hop.hop_number || idx + 1).padStart(2, "0")}
                      </span>
                      ${hop.is_origin ? `
                        <span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-danger text-danger bg-danger/10">
                          ORIGIN SERVER [CONFIRMED]
                        </span>
                      ` : `
                        <span class="text-[10px] font-mono text-muted px-1.5 py-0.5 rounded border border-line bg-ground">
                          Relay Hop
                        </span>
                      `}
                      <span class="text-[10px] font-mono text-muted px-1.5 py-0.5 rounded bg-ground border border-line">
                        Delay: ${escapeHtml(hop.delay || "0s")}
                      </span>
                    </div>
                    <span class="font-mono text-[11px] text-muted">${escapeHtml(hop.timestamp || "")}</span>
                  </div>

                  <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs pt-1">
                    <div class="space-y-1">
                      <div class="text-muted"><span class="font-semibold text-ink">From Server:</span> <span class="font-mono break-all">${escapeHtml(hop.from_server || "Unknown")}</span></div>
                      <div class="text-muted"><span class="font-semibold text-ink">By Server (MTA):</span> <span class="font-mono break-all">${escapeHtml(hop.by_server || "Unknown")}</span></div>
                    </div>
                    <div class="space-y-1">
                      <div class="text-muted">
                        <span class="font-semibold text-ink">IP Address:</span>
                        <span class="font-mono font-bold text-ink">${escapeHtml(hop.ip || "N/A")}</span>
                        <span class="text-[10px] font-mono ml-1 text-muted">(${hop.is_public ? 'Public IP' : 'Private / Internal'})</span>
                      </div>
                      ${hop.geo && hop.geo.country && hop.geo.country !== 'Unknown' ? `
                        <div class="text-muted">
                          <span class="font-semibold text-ink">Location & Network:</span>
                          <span>${escapeHtml(hop.geo.city || "")}${hop.geo.city ? ", " : ""}${escapeHtml(hop.geo.country)}</span>
                          <span class="text-muted font-mono">(${escapeHtml(hop.geo.isp || "Relay")}${hop.geo.asn && hop.geo.asn !== 'N/A' ? ' ' + escapeHtml(hop.geo.asn) : ''})</span>
                        </div>
                      ` : ''}
                    </div>
                  </div>
                </div>
              `).join("")}
            </div>
          </div>
        ` : ''}

        <!-- SECTION 4: SENDER IDENTITY & ORIGINATING SERVER TELEMETRY -->
        <div class="space-y-4 pt-6 border-t border-line">
          <div class="flex items-center justify-between">
            <h3 class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">
              Sender Identity & Originating Server Telemetry
            </h3>
            <span class="text-xs font-mono text-muted">Envelope Verification</span>
          </div>

          <div class="overflow-x-auto rounded-input border border-line bg-ground/30">
            <table class="w-full text-left text-xs border-collapse font-sans">
              <tbody class="divide-y divide-line/60">
                <tr>
                  <td class="py-2.5 px-4 font-semibold text-muted w-44">From Address</td>
                  <td class="py-2.5 px-4 font-mono text-ink">${escapeHtml(sender.from_addr || "Not specified")}</td>
                </tr>
                <tr>
                  <td class="py-2.5 px-4 font-semibold text-muted">Return-Path Envelope</td>
                  <td class="py-2.5 px-4 font-mono text-ink ${sender.is_spoofed && sender.return_domain && sender.from_domain !== sender.return_domain ? 'text-danger font-bold' : ''}">
                    ${escapeHtml(sender.return_path || "None")}
                  </td>
                </tr>
                <tr>
                  <td class="py-2.5 px-4 font-semibold text-muted">Reply-To Routing</td>
                  <td class="py-2.5 px-4 font-mono text-ink ${sender.reply_domain && sender.from_domain !== sender.reply_domain ? 'text-danger font-bold' : ''}">
                    ${escapeHtml(sender.reply_to || "None declared")}
                  </td>
                </tr>
                <tr>
                  <td class="py-2.5 px-4 font-semibold text-muted">Originating Public IP</td>
                  <td class="py-2.5 px-4 font-mono text-ink">
                    <span class="font-bold">${escapeHtml(origin.ip || "Not detected in Received headers")}</span>
                    ${origin.country ? `<span class="ml-2 font-sans text-muted">(${escapeHtml(origin.country)}${origin.city ? ', ' + escapeHtml(origin.city) : ''})</span>` : ''}
                  </td>
                </tr>
                <tr>
                  <td class="py-2.5 px-4 font-semibold text-muted">Hosting Relay / ASN</td>
                  <td class="py-2.5 px-4 font-sans text-ink">${escapeHtml(origin.isp || "Autonomous Relay System")} ${origin.asn ? `(${escapeHtml(origin.asn)})` : ''}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- SECTION 5: ATTACHMENT FORENSICS (IF PRESENT) -->
        ${attachments.length > 0 ? `
          <div class="space-y-4 pt-6 border-t border-line">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">
                  Attachment Forensics (${attachments.length})
                </h3>
                <p class="text-xs text-muted mt-0.5">Isolated static payload inspection (execution blocked)</p>
              </div>
              <span class="text-xs font-mono text-muted">SHA-256 Checksums</span>
            </div>

            <div class="overflow-x-auto rounded-input border border-line bg-panel">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="border-b border-line bg-ground/50 text-muted font-semibold">
                  <tr>
                    <th class="py-2.5 px-3 font-mono font-bold">#</th>
                    <th class="py-2.5 px-3">Filename</th>
                    <th class="py-2.5 px-3">Size</th>
                    <th class="py-2.5 px-3">Type</th>
                    <th class="py-2.5 px-3">Threat Status</th>
                    <th class="py-2.5 px-3">SHA-256 Checksum</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-line/60 font-mono">
                  ${attachments.map((att, idx) => `
                    <tr class="hover:bg-ground/30 transition-colors">
                      <td class="py-2.5 px-3 text-muted font-bold">${String(idx + 1).padStart(2, "0")}</td>
                      <td class="py-2.5 px-3 text-ink font-semibold break-all max-w-[200px]">${escapeHtml(att.filename || "unnamed")}</td>
                      <td class="py-2.5 px-3 text-muted whitespace-nowrap">${escapeHtml(att.size_formatted || `${att.size_bytes} B`)}</td>
                      <td class="py-2.5 px-3 text-muted whitespace-nowrap">${escapeHtml(att.mime_type || "application/octet-stream")}</td>
                      <td class="py-2.5 px-3 whitespace-nowrap">
                        ${att.is_double_ext ? `
                          <span class="text-[10px] font-bold px-1.5 py-0.5 rounded border border-danger text-danger bg-danger/5 uppercase">DOUBLE EXTENSION</span>
                        ` : att.is_dangerous ? `
                          <span class="text-[10px] font-bold px-1.5 py-0.5 rounded border border-danger text-danger bg-danger/5 uppercase">DANGEROUS EXTENSION</span>
                        ` : `
                          <span class="text-[10px] font-bold px-1.5 py-0.5 rounded border border-safe text-safe bg-safe/5 uppercase">CLEAN</span>
                        `}
                      </td>
                      <td class="py-2.5 px-3 text-muted">
                        <div class="flex items-center gap-2">
                          <span class="text-[11px] truncate max-w-[140px]">${escapeHtml(att.sha256 || "N/A")}</span>
                          ${att.sha256 ? `
                            <button
                              type="button"
                              onclick="copyText('${escapeHtml(att.sha256)}', this)"
                              class="text-[10px] px-1.5 py-0.5 border border-line rounded bg-ground text-ink hover:border-ink transition-colors cursor-pointer"
                            >
                              Copy
                            </button>
                          ` : ''}
                        </div>
                      </td>
                    </tr>
                  `).join("")}
                </tbody>
              </table>
            </div>
          </div>
        ` : ''}

        <!-- SECTION 6: FORENSIC FINDINGS & EVIDENCE -->
        <div class="space-y-4 pt-6 border-t border-line">
          <div class="flex items-center justify-between">
            <h3 class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">
              Forensic Findings (${findings.length})
            </h3>
            <span class="text-xs font-mono text-muted">Ranked by Severity</span>
          </div>

          <div class="space-y-3">
            ${findings.map((f) => `
              <div class="p-4 rounded-input border border-line bg-panel space-y-2">
                <div class="flex items-center justify-between gap-2 flex-wrap">
                  <div class="flex items-center gap-2">
                    <span class="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${getSevBadge(f.severity)}">
                      ${escapeHtml(f.severity || "info")}
                    </span>
                    <span class="text-xs font-semibold text-muted font-mono uppercase">${escapeHtml(f.category || "General")}</span>
                  </div>
                  <span class="text-xs font-bold text-ink">${escapeHtml(f.title || "Observation")}</span>
                </div>
                <p class="text-xs text-ink leading-relaxed font-sans">
                  ${escapeHtml(f.explanation || "")}
                </p>
                ${f.evidence ? `
                  <div class="p-2 rounded bg-ground/60 border border-line/60 font-mono text-[11px] text-muted break-all">
                    Evidence: ${escapeHtml(f.evidence)}
                  </div>
                ` : ""}
              </div>
            `).join("")}
          </div>
        </div>

        <!-- SECTION 7: EXTRACTED HYPERLINKS & THREAT INTEL (IF PRESENT) -->
        ${links.length > 0 ? `
          <div class="space-y-4 pt-6 border-t border-line">
            <div class="flex items-center justify-between">
              <div>
                <h3 class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">
                  Extracted Hyperlinks (${links.length})
                </h3>
                <p class="text-xs text-muted mt-0.5">Scanned through CyberScape URL threat intelligence engine</p>
              </div>
              <span class="text-xs font-mono text-muted">Defanged Destinations</span>
            </div>

            <div class="overflow-x-auto rounded-input border border-line bg-panel">
              <table class="w-full text-left text-xs border-collapse">
                <thead class="border-b border-line bg-ground/50 text-muted font-semibold">
                  <tr>
                    <th class="py-2.5 px-3 font-mono font-bold">#</th>
                    <th class="py-2.5 px-3">Destination Domain</th>
                    <th class="py-2.5 px-3">Defanged URL</th>
                    <th class="py-2.5 px-3">Threat Status</th>
                    <th class="py-2.5 px-3">Anomalies & Signals</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-line/60 font-mono">
                  ${links.map((l, idx) => {
                    const status = (l.threat_status || (l.is_malicious ? 'MALICIOUS' : 'SAFE')).toUpperCase();
                    let stBadge = "border-safe text-safe bg-safe/5";
                    if (status === "MALICIOUS") stBadge = "border-danger text-danger bg-danger/5";
                    else if (status === "SUSPICIOUS") stBadge = "border-suspicious text-suspicious bg-suspicious/5";

                    return `
                      <tr class="hover:bg-ground/30 transition-colors">
                        <td class="py-2.5 px-3 text-muted font-bold">${String(idx + 1).padStart(2, "0")}</td>
                        <td class="py-2.5 px-3 text-ink font-semibold">${escapeHtml(l.domain || "Direct Destination")}</td>
                        <td class="py-2.5 px-3 text-muted break-all max-w-[240px]">${escapeHtml(l.defanged_url || l.original_url)}</td>
                        <td class="py-2.5 px-3 whitespace-nowrap">
                          <span class="text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${stBadge}">
                            ${status}
                          </span>
                        </td>
                        <td class="py-2.5 px-3">
                          <div class="flex items-center gap-1.5 flex-wrap">
                            ${l.is_ip ? `<span class="text-[10px] font-bold px-1.5 py-0.5 rounded border border-danger text-danger bg-danger/5 uppercase">RAW IP</span>` : ''}
                            ${l.href_mismatch ? `<span class="text-[10px] font-bold px-1.5 py-0.5 rounded border border-danger text-danger bg-danger/5 uppercase">HREF MISMATCH</span>` : ''}
                            ${l.is_shortener ? `<span class="text-[10px] font-bold px-1.5 py-0.5 rounded border border-suspicious text-suspicious bg-suspicious/5 uppercase">SHORTENER</span>` : ''}
                            ${l.threat_signals && l.threat_signals.length ? `
                              <span class="text-[10px] text-muted font-sans">${escapeHtml(l.threat_signals.join(", "))}</span>
                            ` : ''}
                            ${!l.is_ip && !l.href_mismatch && !l.is_shortener && (!l.threat_signals || !l.threat_signals.length) ? `<span class="text-[10px] text-muted">Standard</span>` : ''}
                          </div>
                        </td>
                      </tr>
                    `;
                  }).join("")}
                </tbody>
              </table>
            </div>
          </div>
        ` : ''}

        <!-- SECTION 8: RECOMMENDATIONS -->
        ${recs.length > 0 ? `
          <div class="space-y-3 pt-6 border-t border-line">
            <h3 class="text-xs uppercase tracking-wider text-muted font-semibold font-mono">
              Actionable Security Recommendations
            </h3>
            <ul class="space-y-2 text-xs text-muted font-sans">
              ${recs.map(r => `
                <li class="flex items-start gap-2">
                  <span class="text-ink font-bold">•</span>
                  <span>${escapeHtml(r)}</span>
                </li>
              `).join("")}
            </ul>
          </div>
        ` : ''}

        <!-- Footnote -->
        <p class="text-xs text-muted pt-4 border-t border-line/60 font-mono leading-relaxed">
          Forensic analysis evaluates RFC 822 email envelopes, cryptographic message signatures, payload hashes, and psychological intent heuristics. Always independently confirm high-value payment requests.
        </p>
      </div>
    `;

    if (window.lucide && typeof window.lucide.createIcons === "function") {
      window.lucide.createIcons();
    }

    if (el.scrollIntoView) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // Upload EML Handler
  async function handleEmlUpload(file) {
    const resultContainer = document.getElementById("emailScanResult");
    const emlUploadStatus = document.getElementById("emlUploadStatus");

    if (!file) return;

    if (file.size > 15 * 1024 * 1024) {
      if (emlUploadStatus) emlUploadStatus.innerText = "Error: File exceeds maximum allowed size (15 MB).";
      alert("Selected file exceeds maximum allowed size (15 MB).");
      return;
    }

    const sizeFormatted = file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`;
    if (emlUploadStatus) {
      emlUploadStatus.innerText = `Analyzing: ${file.name} (${sizeFormatted})...`;
    }

    if (resultContainer) {
      resultContainer.className = "w-full mt-8";
      resultContainer.innerHTML = `
        <div class="p-6 rounded-[12px] border border-line bg-panel text-ink space-y-4 animate-pulse">
          <div class="flex items-center justify-between pb-3 border-b border-line">
            <span class="text-xs font-mono font-bold uppercase text-muted">Inspecting .EML Archive</span>
            <span class="text-xs font-mono text-muted">Decompressing MIME tree & computing SHA-256 hashes...</span>
          </div>
          <div class="h-4 bg-line/40 rounded w-2/3"></div>
          <div class="h-16 bg-line/20 rounded w-full"></div>
        </div>
      `;
    }

    try {
      const formData = new FormData();
      formData.append("eml_file", file);

      const res = await fetch("/analyze-email", {
        method: "POST",
        body: formData
      });

      if (!res.ok) {
        let errMsg = "Forensic inspection of .eml file failed.";
        try {
          const errJson = await res.json();
          errMsg = errJson.error || errMsg;
        } catch (e) {}
        throw new Error(errMsg);
      }

      const data = await res.json();
      if (emlUploadStatus) {
        emlUploadStatus.innerText = `Analyzed: ${file.name} (${sizeFormatted}) - Complete.`;
      }
      renderEmailResult(data, resultContainer);
    } catch (err) {
      if (emlUploadStatus) {
        emlUploadStatus.innerText = `Failed: ${err.message || 'Error processing .eml file'}`;
      }
      if (resultContainer) {
        resultContainer.className = "w-full mt-6";
        resultContainer.innerHTML = `
          <div class="p-6 rounded-input border border-danger/40 bg-panel text-ink space-y-3">
            <div class="flex items-center gap-2 text-danger font-bold text-xs uppercase">
              <span class="w-2.5 h-2.5 rounded-full bg-danger"></span>
              <span>Analysis Failed</span>
            </div>
            <p class="text-xs text-muted leading-relaxed font-sans">
              ${escapeHtml(err.message || "An unexpected error occurred during email forensic inspection.")}
            </p>
          </div>
        `;
      }
    }
  }

  // Initialize event listeners when DOM is loaded
  document.addEventListener("DOMContentLoaded", function () {
    const analyzeBtn = document.getElementById("analyzeEmailBtn");
    const headerInput = document.getElementById("headerInput");
    const contentInput = document.getElementById("contentInput");
    const resultContainer = document.getElementById("emailScanResult");

    const emlFileInput = document.getElementById("emlFile");
    const emlDropZone = document.getElementById("emlDropZone");

    if (analyzeBtn) {
      analyzeBtn.addEventListener("click", async function () {
        const headerText = (headerInput ? headerInput.value : "").trim();
        const contentText = (contentInput ? contentInput.value : "").trim();

        if (!headerText && !contentText) {
          if (resultContainer) {
            resultContainer.className = "w-full mt-6";
            resultContainer.innerHTML = `
              <div class="p-4 rounded-input border border-danger/40 bg-panel text-danger text-xs font-semibold">
                Please paste an email header or email subject and body content to analyze.
              </div>
            `;
          }
          return;
        }

        const origHtml = analyzeBtn.innerHTML;
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = `
          <span class="inline-flex items-center gap-2">
            <span class="w-3.5 h-3.5 border-2 border-ground border-t-transparent rounded-full animate-spin"></span>
            <span>Analyzing Email Forensics...</span>
          </span>
        `;

        if (resultContainer) {
          resultContainer.className = "w-full mt-8";
          resultContainer.innerHTML = `
            <div class="p-6 rounded-[12px] border border-line bg-panel text-ink space-y-4 animate-pulse">
              <div class="flex items-center justify-between pb-3 border-b border-line">
                <span class="text-xs font-mono font-bold uppercase text-muted">Inspection in progress</span>
                <span class="text-xs font-mono text-muted">Running verification engines & link analysis...</span>
              </div>
              <div class="h-4 bg-line/40 rounded w-2/3"></div>
              <div class="h-16 bg-line/20 rounded w-full"></div>
            </div>
          `;
        }

        try {
          const res = await fetch("/analyze-email", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Accept": "application/json"
            },
            body: JSON.stringify({
              header: headerText,
              body: contentText
            })
          });

          if (!res.ok) {
            let errMsg = "Forensic analysis failed.";
            try {
              const errJson = await res.json();
              errMsg = errJson.error || errMsg;
            } catch (e) {}
            throw new Error(errMsg);
          }

          const data = await res.json();
          renderEmailResult(data, resultContainer);
        } catch (err) {
          if (resultContainer) {
            resultContainer.className = "w-full mt-6";
            resultContainer.innerHTML = `
              <div class="p-6 rounded-input border border-danger/40 bg-panel text-ink space-y-3">
                <div class="flex items-center gap-2 text-danger font-bold text-xs uppercase">
                  <span class="w-2.5 h-2.5 rounded-full bg-danger"></span>
                  <span>Analysis Failed</span>
                </div>
                <p class="text-xs text-muted leading-relaxed font-sans">
                  ${escapeHtml(err.message || "An unexpected error occurred during email forensic inspection.")}
                </p>
                <button
                  type="button"
                  onclick="document.getElementById('analyzeEmailBtn').click()"
                  class="py-2 px-4 bg-ink text-ground rounded-btn text-xs font-semibold hover:bg-ink/90 transition-colors cursor-pointer"
                >
                  Retry Analysis
                </button>
              </div>
            `;
          }
        } finally {
          analyzeBtn.disabled = false;
          analyzeBtn.innerHTML = origHtml;
        }
      });
    }

    // EML File input listener
    if (emlFileInput) {
      emlFileInput.addEventListener("change", function (e) {
        if (e.target.files && e.target.files[0]) {
          handleEmlUpload(e.target.files[0]);
        }
      });
    }

    // EML Dropzone listeners
    if (emlDropZone) {
      ["dragenter", "dragover"].forEach((eventName) => {
        emlDropZone.addEventListener(eventName, function (e) {
          e.preventDefault();
          e.stopPropagation();
          emlDropZone.classList.add("border-ink", "bg-ground/40");
        }, false);
      });

      ["dragleave", "drop"].forEach((eventName) => {
        emlDropZone.addEventListener(eventName, function (e) {
          e.preventDefault();
          e.stopPropagation();
          emlDropZone.classList.remove("border-ink", "bg-ground/40");
        }, false);
      });

      emlDropZone.addEventListener("drop", function (e) {
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
          const file = e.dataTransfer.files[0];
          handleEmlUpload(file);
        }
      }, false);
    }
  });
})();

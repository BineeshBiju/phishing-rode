let currentEmailAnalysis = null;

function switchTrack(track) {
  const paneHeader = document.getElementById("paneHeader");
  const paneContent = document.getElementById("paneContent");
  if (paneHeader) paneHeader.style.display = "block";
  if (paneContent) paneContent.style.display = "block";
}

function clearInputs() {
  document.getElementById("headerInput").value = "";
  document.getElementById("contentInput").value = "";
  const el = document.getElementById("emailScanResult");
  el.className = "result hidden";
  el.innerHTML = "";
  currentEmailAnalysis = null;
}

const SAMPLE_DATA = {
  spoofed_paypal: {
    header: `From: "PayPal Security Team" <security@update-paypal-notice.xyz>
Return-Path: <bounce-service@host-node19.ru>
Reply-To: <credential-harvest@offshore-mail.ru>
Received: from mail.host-node19.ru (mail.host-node19.ru [185.220.101.5]) by mx.google.com
Received-SPF: fail (google.com: domain of update-paypal-notice.xyz does not designate 185.220.101.5 as permitted sender)
Authentication-Results: mx.google.com; spf=fail (google.com: domain of update-paypal-notice.xyz does not designate 185.220.101.5); dkim=fail; dmarc=fail
Subject: Critical Security Warning: PayPal Account Suspended within 24 Hours`,
    content: `Subject: Critical Security Warning: PayPal Account Suspended within 24 Hours

Dear PayPal Customer,

We detected unauthorized login attempts and fraudulent access on your PayPal account from an unrecognized IP address in Moscow, Russia. Your account will be permanently suspended within 24 hours unless you verify your identity immediately.

Click here to confirm your credentials and update billing information:
http://185.220.101.5/paypal/account-verification.xyz/login

Failure to verify immediately will result in immediate termination of all funds and account balance.

PayPal Fraud Prevention Department`
  },
  ceo_fraud: {
    header: `From: "John Anderson (CEO)" <ceo.executive.desk@gmail.com>
Return-Path: <ceo.executive.desk@gmail.com>
Reply-To: <urgent-wire-transfer@offshore-consulting.com>
Received: from mail-ed1-f52.google.com ([209.85.208.52])
Subject: URGENT: Wire Transfer Authorization Required Before 3PM`,
    content: `Subject: URGENT: Wire Transfer Authorization Required Before 3PM

Are you at your desk right now? I am currently in a high-priority confidential executive board meeting and cannot take voice calls.

We need to send an immediate wire deposit of $42,500 to an offshore vendor for an acquisition deal before 3 PM today. Please confirm your availability to process this payment right now. Do not discuss this with anyone in the office yet.

John Anderson
Chief Executive Officer`
  },
  legitimate: {
    header: `From: "GitHub" <noreply@github.com>
Return-Path: <noreply@github.com>
Received: from smtp.github.com (smtp.github.com [140.82.112.4]) by mx.google.com
Received-SPF: pass (google.com: domain of noreply@github.com designates 140.82.112.4 as permitted sender)
Authentication-Results: mx.google.com; dkim=pass header.i=@github.com; spf=pass; dmarc=pass
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=s2024;
Subject: [GitHub] A personal access token has expired`,
    content: `Subject: [GitHub] A personal access token has expired

Hi developer,

Your personal access token (deployment-token-ci) expired on October 15, 2026.

You can review your active developer tokens and generate a replacement in your GitHub security settings:
https://github.com/settings/tokens

If you no longer need this token, no further action is required.

Thanks,
The GitHub Team`
  }
};

function loadSample(key) {
  const s = SAMPLE_DATA[key];
  if (!s) return;
  document.getElementById("headerInput").value = s.header;
  document.getElementById("contentInput").value = s.content;
  switchTrack("both");
}

async function downloadEmailReport() {
  if (!currentEmailAnalysis) {
    alert("Please analyze an email first.");
    return;
  }
  const btn = document.getElementById("emailReportBtn");
  const origHtml = btn ? btn.innerHTML : "📄 Download Email Forensic PDF Report";
  if (btn) {
    btn.innerHTML = '<span class="icon">⏳</span> Generating PDF...';
    btn.disabled = true;
  }

  try {
    const res = await fetch("/api/generate-email-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentEmailAnalysis)
    });
    if (!res.ok) throw new Error("Failed to generate PDF");

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
}

function inspectUrlInScanner(url) {
  try {
    sessionStorage.setItem("pendingScanUrl", url);
    window.location.href = "/scanner";
  } catch (e) {
    window.location.href = "/scanner";
  }
}

function renderEmailResult(data, el) {
  currentEmailAnalysis = data;
  const statusLower = (data.verdict || "unknown").toLowerCase();
  el.className = "result " + statusLower;

  const score = data.score || 0;
  const header = data.header_analysis || {};
  const content = data.content_analysis || {};
  const auth = header.authentication || {};
  const summary = data.summary || {};
  const geo = header.geo_ip || {};
  const urls = content.extracted_urls || [];
  const triggers = content.urgency_triggers || [];
  const impersonations = content.brand_impersonations || [];

  // Gauge percentage calculation
  const gaugeColor = score >= 70 ? 'var(--status-malicious)' : (score >= 35 ? 'var(--status-suspicious)' : 'var(--status-safe)');

  el.innerHTML = `
    <div class="result-card-container">
      <!-- Section A: Top Verdict Bar & Visual Gauge -->
      <div class="result-header">
        <div class="result-target">
          <div class="eyebrow">EMAIL FORENSIC VERDICT</div>
          <h2>${escapeHtml(header.subject || header.from_addr || "Analyzed Email Communication")}</h2>
          <div class="sender-subline">
            <b>Claimed Sender:</b> <code>${escapeHtml(header.from_header || header.from_addr || 'Unspecified')}</code>
          </div>
          <div class="status-badge ${statusLower}">
            <span class="status-dot"></span>
            ${escapeHtml(data.verdict)} • ${escapeHtml(data.level)}
          </div>
        </div>

        <!-- Visual Safety Score Gauge -->
        <div class="score-card ${statusLower}">
          <div class="score-label">DECEPTION & THREAT GAUGE</div>
          <div class="gauge-meter-wrapper">
            <div class="score ${statusLower}">${score}<small>/100</small></div>
            <div class="gauge-bar-outer">
              <div class="gauge-bar-fill" style="width: ${score}%; background: ${gaugeColor};"></div>
            </div>
            <span class="gauge-risk-tag">${score >= 70 ? 'High Risk Fake Email' : (score >= 35 ? 'Elevated Risk / Spoofed' : 'Authenticated & Safe')}</span>
          </div>
        </div>
      </div>

      <!-- Section B: Key Verdict Badges requested -->
      <div class="verdict-badges-bar">
        <!-- Badge 1: Authentication -->
        <div class="metric-badge ${auth.level === 'FAIL' ? 'badge-danger' : (auth.level === 'PASS' ? 'badge-success' : 'badge-warning')}">
          <span class="badge-lbl">AUTHENTICATION</span>
          <span class="badge-val">
            ${auth.level === 'FAIL' ? '❌ FAILED (Spoofed Domain)' : (auth.level === 'PASS' ? '✓ PASSED' : '⚠️ UNVERIFIED')}
          </span>
        </div>

        <!-- Badge 2: Originating Country & IP -->
        <div class="metric-badge badge-neutral">
          <span class="badge-lbl">ORIGINATING SERVER</span>
          <span class="badge-val">
            <span class="flag-icon">${geo.flag || '🌐'}</span>
            ${escapeHtml(geo.country || 'Unknown')} <code>[${escapeHtml(summary.originating_ip || 'N/A')}]</code>
          </span>
        </div>

        <!-- Badge 3: Phishing Intent -->
        <div class="metric-badge ${summary.phishing_intent === 'HIGH' ? 'badge-danger' : (summary.phishing_intent === 'MEDIUM' ? 'badge-warning' : 'badge-success')}">
          <span class="badge-lbl">PHISHING INTENT</span>
          <span class="badge-val">
            ${summary.phishing_intent === 'HIGH' ? '🚨 HIGH INTENT' : (summary.phishing_intent === 'MEDIUM' ? '⚠️ MEDIUM INTENT' : '✓ LOW / INFORMATIONAL')}
          </span>
        </div>
      </div>

      <!-- Section C: Action Buttons -->
      <div class="forensic-action-bar">
        <button class="btn btn-pdf-primary" id="emailReportBtn" onclick="downloadEmailReport()">
          <span class="icon">📄</span> Download Email Forensic PDF Report
        </button>
        ${urls.length > 0 ? `
          <button class="btn ghost" onclick="inspectUrlInScanner('${escapeHtml(urls[0].original_url)}')">
            Re-check Extracted URLs (${urls.length}) →
          </button>
        ` : ''}
      </div>

      <!-- Section D: Technical Header & Spoofing Audit -->
      <div class="security-card rounded-2xl">
        <div class="card-head">
          <div class="card-title">
            <span class="badge-icon">⚙️</span>
            <h4>Technical Header & Sender Authenticity Audit</h4>
          </div>
          <div class="ml-score-badge ${header.is_spoofed ? 'danger' : 'safe'}">
            <span class="ml-badge-dot"></span>
            <b>${header.is_spoofed ? 'Domain Spoofing Detected' : 'Domain Alignment Valid'}</b>
          </div>
        </div>
        <div class="telemetry-grid">
          <div class="tel-item">
            <div class="tel-label">FROM SENDER DOMAIN</div>
            <div class="tel-val font-mono">${escapeHtml(header.from_domain || 'N/A')}</div>
          </div>
          <div class="tel-item">
            <div class="tel-label">RETURN-PATH DOMAIN</div>
            <div class="tel-val font-mono">${escapeHtml(header.return_domain || 'N/A')}</div>
          </div>
          <div class="tel-item">
            <div class="tel-label">SPF VALIDATION</div>
            <div class="tel-val font-mono ${auth.spf === 'FAIL' ? 'text-danger' : (auth.spf === 'PASS' ? 'text-safe' : '')}">${auth.spf || 'NONE'}</div>
          </div>
          <div class="tel-item">
            <div class="tel-label">DKIM & DMARC</div>
            <div class="tel-val font-mono">DKIM: ${auth.dkim || 'NONE'} | DMARC: ${auth.dmarc || 'NONE'}</div>
          </div>
        </div>
        ${header.spoofing_flags && header.spoofing_flags.length ? `
          <div class="factors-box" style="margin-top:14px;">
            <div class="factors-title">Spoofing Indicators Identified:</div>
            <ul class="factors-list">
              ${header.spoofing_flags.map(flag => `<li><span class="bullet">⚠</span> ${escapeHtml(flag)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}
      </div>

      <!-- Section E: Originating IP Geo-Telemetry -->
      <div class="security-card geo-card rounded-2xl">
        <div class="card-head">
          <div class="card-title">
            <span class="badge-icon">🌐</span>
            <h4>Sender Originating IP & Infrastructure Telemetry</h4>
          </div>
          <div class="geo-flag-badge">
            <span class="country-flag-icon">${geo.flag || '🌐'}</span>
            <span>${escapeHtml(geo.country || 'Global Network')}</span>
          </div>
        </div>
        <div class="telemetry-grid">
          <div class="tel-item">
            <div class="tel-label">ORIGINATING CLIENT IP</div>
            <div class="tel-val font-mono">${escapeHtml(summary.originating_ip || 'Unresolved')}</div>
          </div>
          <div class="tel-item">
            <div class="tel-label">HOST LOCATION</div>
            <div class="tel-val">${escapeHtml(geo.city || 'Autonomous')}, ${escapeHtml(geo.region || 'Region')}</div>
          </div>
          <div class="tel-item">
            <div class="tel-label">ISP & ASN</div>
            <div class="tel-val">${escapeHtml(geo.isp || 'Relay Provider')}</div>
          </div>
          <div class="tel-item">
            <div class="tel-label">COORDINATES & MAP</div>
            <div class="tel-val tel-coords">
              <span class="font-mono">${escapeHtml(geo.coordinates || '0.0000, 0.0000')}</span>
              ${geo.latitude && geo.longitude ? `
                <a class="coords-btn" href="https://www.openstreetmap.org/?mlat=${geo.latitude}&mlon=${geo.longitude}#map=11/${geo.latitude}/${geo.longitude}" target="_blank" rel="noopener noreferrer">
                  Map ↗
                </a>
              ` : ''}
            </div>
          </div>
        </div>
      </div>

      <!-- Section F: NLP Content & Deception Triggers -->
      <div class="security-card rounded-2xl">
        <div class="card-head">
          <div class="card-title">
            <span class="badge-icon">🧠</span>
            <h4>AI Email Text & Phishing Intent NLP Analysis</h4>
          </div>
          <div class="ml-score-badge ${content.phishing_intent === 'HIGH' ? 'danger' : (content.phishing_intent === 'MEDIUM' ? 'warning' : 'safe')}">
            <span class="ml-badge-dot"></span>
            <b>Intent: ${escapeHtml(content.phishing_intent || 'LOW')}</b>
            <span class="ml-conf">(${content.urgency_score || 0}/100 Urgency Index)</span>
          </div>
        </div>

        ${impersonations.length > 0 ? `
          <div class="impersonation-alert-card">
            <div class="alert-icon">⚠️</div>
            <div>
              <div class="alert-title">Brand Impersonation Alert</div>
              <ul class="alert-list">
                ${impersonations.map(imp => `<li><b>${escapeHtml(imp.brand)}</b>: ${escapeHtml(imp.reason)}</li>`).join('')}
              </ul>
            </div>
          </div>
        ` : ''}

        ${triggers.length > 0 ? `
          <div class="factors-box">
            <div class="factors-title">Deceptive Urgency & Panic Triggers Detected:</div>
            <ul class="factors-list">
              ${triggers.map(t => `
                <li>
                  <span class="bullet">⚠</span>
                  <span><i>"${escapeHtml(t.phrase)}"</i> — ${escapeHtml(t.reason)}</span>
                </li>
              `).join('')}
            </ul>
          </div>
        ` : `
          <div class="factors-safe">
            <span class="icon">✓</span> Zero panic-inducing or coercive phishing trigger expressions detected in message text.
          </div>
        `}
      </div>

      <!-- Section G: Defanged Extracted Hyperlinks -->
      ${urls.length > 0 ? `
        <div class="security-card rounded-2xl">
          <div class="card-head">
            <div class="card-title">
              <span class="badge-icon">🔗</span>
              <h4>Extracted Hyperlinks Sandbox (Defanged)</h4>
            </div>
            <span class="badge-neutral" style="padding:4px 10px; border-radius:999px; font-family:var(--font-mono); font-size:0.75rem;">
              ${urls.length} Link(s) Extracted
            </span>
          </div>
          <div class="extracted-links-table-wrapper">
            <table class="forensic-links-table">
              <thead>
                <tr>
                  <th>Defanged URL</th>
                  <th>Target Domain</th>
                  <th>Risk Indicator</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                ${urls.map(u => `
                  <tr>
                    <td class="font-mono text-break">${escapeHtml(u.defanged_url)}</td>
                    <td class="font-mono">${escapeHtml(u.domain)}</td>
                    <td>
                      ${u.is_ip ? '<span class="chip-danger">⚠️ Raw IP</span>' : '<span class="chip-neutral">Standard Domain</span>'}
                    </td>
                    <td>
                      <button class="btn btn-inspect-link" onclick="inspectUrlInScanner('${escapeHtml(u.original_url)}')">
                        Inspect Link ➔
                      </button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      ` : ''}

      <!-- Section H: Master Risk Factors -->
      <div class="security-card rounded-2xl">
        <div class="card-head">
          <div class="card-title">
            <span class="badge-icon">📋</span>
            <h4>Master Forensic Risk Factors</h4>
          </div>
        </div>
        <ul class="reasons">
          ${(data.risk_factors || []).map(r => `<li>✓ ${escapeHtml(r)}</li>`).join('')}
        </ul>
      </div>
    </div>
  `;
}

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("analyzeEmailBtn");
  if (btn) {
    btn.addEventListener("click", async () => {
      const headerText = document.getElementById("headerInput").value.trim();
      const contentText = document.getElementById("contentInput").value.trim();
      const el = document.getElementById("emailScanResult");

      if (!headerText && !contentText) {
        el.className = "result malicious";
        el.innerHTML = '<div class="factors-safe" style="color:var(--status-malicious-text)">⚠️ Please paste an email header, sender details, or message content to analyze.</div>';
        return;
      }

      // Intercept unauthenticated users
      if (window.CYBER_AUTH && !window.CYBER_AUTH.isAuthenticated) {
        openAuthModal();
        return;
      }

      const origBtnHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="pulse-indicator"></span> Running Multi-Track Forensics...';
      el.className = "result";
      el.innerHTML = '<div class="loading-state"><span class="pulse-indicator"></span> Tracing sender authenticity, SPF/DKIM verification, NLP intent detection, and originating IP...</div>';

      try {
        const res = await fetch("/api/analyze-email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            header_text: headerText,
            content_text: contentText
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Analysis failed");
        renderEmailResult(data, el);
      } catch (err) {
        el.className = "result malicious";
        el.innerHTML = `<div class="factors-safe" style="color:var(--status-malicious-text)">❌ Forensic Analysis Error: ${escapeHtml(err.message)}</div>`;
      } finally {
        btn.disabled = false;
        btn.innerHTML = origBtnHtml;
      }
    });
  }
});

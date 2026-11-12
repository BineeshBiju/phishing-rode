/*
 * Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
 * See LICENSE for details.
 */

/**
 * CyberScape Reusable ScanResultPanel & URL Scanner App
 * Enterprise-grade, editorial, restrained design with flat layout, Tailwind tokens,
 * full-width rectangular result panel, zero inner scrollbars, explainable signals,
 * robust state machine (idle, loading, success, error), and accessibility support.
 */

(function () {
  if (typeof React === "undefined" || typeof ReactDOM === "undefined") {
    return;
  }

  const { useState, useEffect, useRef } = React;
  const h = React.createElement;

  const SEVERITY_ORDER = {
    critical: 4,
    danger: 4,
    high: 4,
    warning: 3,
    suspicious: 3,
    medium: 3,
    low: 2,
    info: 1,
    safe: 0
  };

  /**
   * Derive display verdict according to strict rule 3e:
   * - Never show "Low risk, verified safe" when the destination was "Unreachable"
   *   or when 2 or more reputation sources are UNAVAILABLE.
   * - In those cases show a neutral verdict "Inconclusive, not enough data" in a neutral color (muted text, not green).
   * - Show "verified safe" only if the destination was reached and at least two reputation sources actually responded clean.
   */
  function computeDisplayVerdict(report) {
    if (!report) {
      return {
        status: "UNKNOWN",
        level: "Unknown",
        verdictLabel: "No inspection data",
        colorClass: "text-muted",
        badgeClass: "border border-line text-muted bg-ground",
        summarySentence: "No destination data available.",
        confidence: 0
      };
    }

    const score = report.score !== undefined ? Number(report.score) : 0;
    const rawStatus = (report.status || "UNKNOWN").toUpperCase();

    // Check 1: Destination unreachable or invalid
    const chain = (report.redirect_chain && report.redirect_chain.chain) || [];
    let isUnreachable = false;
    let unreachableReason = "";

    if (chain.length > 0) {
      const lastHop = chain[chain.length - 1];
      if (
        lastHop.status_code === 0 ||
        lastHop.status_code >= 400 ||
        (lastHop.reason && /unreachable|connection terminated|blocked/i.test(lastHop.reason))
      ) {
        isUnreachable = true;
        unreachableReason = lastHop.reason || "Destination host could not be reached.";
      }
    }
    if (rawStatus === "INVALID") {
      isUnreachable = true;
      unreachableReason = (report.reasons && report.reasons[0]) || "Invalid destination URL.";
    }

    // Check 2: Reputation sources status
    const sourcesChecked = report.sources_checked || {};
    const repKeys = ["urlhaus", "virustotal", "safebrowsing", "openphish"];
    let unavailCount = 0;
    let cleanCount = 0;
    const unavailNames = [];

    repKeys.forEach((k) => {
      const s = sourcesChecked[k];
      if (!s || s.status === "UNAVAILABLE" || s.available === false) {
        unavailCount++;
        unavailNames.push((s && s.name) || k);
      } else if (
        s.status === "SAFE" ||
        s.status === "OK" ||
        s.status === "NO_MATCH" ||
        s.status === "STANDBY"
      ) {
        cleanCount++;
      }
    });

    const isMalicious = rawStatus === "MALICIOUS" || score >= 70;
    const isSuspicious = !isMalicious && (rawStatus === "SUSPICIOUS" || score >= 30);

    if (isMalicious) {
      return {
        status: "MALICIOUS",
        level: "High Risk",
        verdictLabel: "High risk, do not open",
        colorClass: "text-danger",
        badgeClass: "border border-danger text-danger bg-danger/5",
        summarySentence:
          (report.reasons && report.reasons[0]) ||
          "Confirmed threat patterns detected in live databases or heuristic models.",
        confidence: report.confidence !== undefined ? report.confidence : 95
      };
    }

    if (isSuspicious) {
      return {
        status: "SUSPICIOUS",
        level: "Suspicious",
        verdictLabel: "Suspicious, proceed with caution",
        colorClass: "text-suspicious",
        badgeClass: "border border-suspicious text-suspicious bg-suspicious/5",
        summarySentence:
          (report.reasons && report.reasons[0]) ||
          "Anomalous domain characteristics, redirect hops, or heuristic indicators detected.",
        confidence: report.confidence !== undefined ? report.confidence : 80
      };
    }

    // Rule 3e: Inconclusive check for safe / low score results (applies to remote Web URLs)
    const isWebUrl = !report.payload_type || report.payload_type === "URL";
    const isInconclusive = isWebUrl && (isUnreachable || unavailCount >= 2 || cleanCount < 2);

    if (isInconclusive) {
      let reasonText = "Insufficient data to verify safety.";
      if (isUnreachable) {
        reasonText = `Destination unreachable (${unreachableReason}); safety cannot be verified.`;
      } else if (unavailCount >= 2) {
        reasonText = `Multiple threat reputation feeds were unavailable (${unavailNames.slice(0, 2).join(", ")}); insufficient live data.`;
      } else {
        reasonText = "Fewer than two threat reputation feeds responded clean.";
      }

      return {
        status: "INCONCLUSIVE",
        level: "Inconclusive",
        verdictLabel: "Inconclusive, not enough data",
        colorClass: "text-muted",
        badgeClass: "border border-line text-muted bg-ground",
        summarySentence: reasonText,
        confidence: Math.min(report.confidence !== undefined ? report.confidence : 45, 50)
      };
    }

    // Verified safe: reached AND at least two reputation feeds responded clean
    return {
      status: "SAFE",
      level: "Low Risk",
      verdictLabel: "Low risk, verified safe",
      colorClass: "text-safe",
      badgeClass: "border border-safe text-safe bg-safe/5",
      summarySentence:
        (report.reasons && report.reasons[0]) ||
        "No threat records returned across multiple live threat intelligence feeds.",
      confidence: report.confidence !== undefined ? report.confidence : 96
    };
  }

  /**
   * Reusable Loading Skeleton for Scan Result
   */
  function ScanResultSkeleton(props) {
    const url = props.url || "Destination link";
    return h(
      "div",
      {
        role: "region",
        "aria-label": "Scan result loading",
        "aria-live": "polite",
        className:
          "bg-panel rounded-[12px] border border-line p-6 sm:p-8 w-full max-w-[1240px] mx-auto text-ink animate-pulse shadow-sm"
      },
      // Summary bar skeleton
      h(
        "div",
        { className: "pb-6 sm:pb-8 flex flex-col md:flex-row md:items-start justify-between gap-6" },
        h(
          "div",
          { className: "flex-grow space-y-3" },
          h(
            "div",
            { className: "flex items-center gap-2" },
            h("span", { className: "w-2.5 h-2.5 rounded-full bg-danger animate-ping" }),
            h(
              "span",
              { className: "text-xs uppercase tracking-wider text-muted font-semibold" },
              "Threat Inspection In Progress"
            )
          ),
          h("div", { className: "h-9 bg-line/40 rounded w-3/4 max-w-[360px]" }),
          h(
            "p",
            { className: "text-sm text-muted font-mono break-all" },
            `Checking redirects and threat feeds for: ${url}`
          )
        ),
        h(
          "div",
          { className: "flex flex-col items-start md:items-end space-y-2 shrink-0" },
          h("div", { className: "h-10 bg-line/40 rounded w-28" }),
          h("div", { className: "h-4 bg-line/40 rounded w-36" })
        )
      ),
      // Two-column skeleton
      h(
        "div",
        {
          className:
            "pt-6 sm:pt-8 pb-6 sm:pb-8 border-t border-line grid grid-cols-1 md:grid-cols-2 gap-8"
        },
        h(
          "div",
          { className: "space-y-3" },
          h("div", { className: "h-4 bg-line/40 rounded w-28 mb-4" }),
          h("div", { className: "h-12 bg-line/30 rounded" }),
          h("div", { className: "h-12 bg-line/20 rounded" })
        ),
        h(
          "div",
          { className: "space-y-3" },
          h("div", { className: "h-4 bg-line/40 rounded w-28 mb-4" }),
          h(
            "div",
            { className: "grid grid-cols-1 sm:grid-cols-2 gap-2.5" },
            h("div", { className: "h-10 bg-line/30 rounded" }),
            h("div", { className: "h-10 bg-line/30 rounded" }),
            h("div", { className: "h-10 bg-line/30 rounded" }),
            h("div", { className: "h-10 bg-line/30 rounded" })
          )
        )
      ),
      // Network & Location skeleton
      h(
        "div",
        { className: "pt-6 sm:pt-8 pb-6 sm:pb-8 border-t border-line space-y-3" },
        h(
          "div",
          { className: "flex items-center justify-between" },
          h("div", { className: "h-4 bg-line/40 rounded w-44" }),
          h("div", { className: "h-4 bg-line/30 rounded w-28" })
        ),
        h("div", { className: "h-5 bg-line/30 rounded w-3/4 max-w-[480px]" }),
        h("div", { className: "h-28 bg-line/20 rounded w-full" })
      ),
      // Signals skeleton
      h(
        "div",
        { className: "pt-6 sm:pt-8 border-t border-line space-y-3" },
        h("div", { className: "h-4 bg-line/40 rounded w-36 mb-4" }),
        h("div", { className: "h-14 bg-line/30 rounded" }),
        h("div", { className: "h-14 bg-line/20 rounded" })
      )
    );
  }

  /**
   * Reusable Error Card for Scan Failures
   */
  function ScanResultError(props) {
    const { error, url, onRetry, onScanAnother } = props;
    return h(
      "div",
      {
        role: "region",
        "aria-label": "Scan error",
        "aria-live": "polite",
        className:
          "bg-panel rounded-[12px] border border-danger/40 p-6 sm:p-8 w-full max-w-[1240px] mx-auto text-ink shadow-sm"
      },
      h(
        "div",
        { className: "flex items-center justify-between pb-4 border-b border-line mb-5" },
        h(
          "div",
          {
            className:
              "flex items-center gap-2 text-danger font-bold text-sm uppercase tracking-wider"
          },
          h("span", { className: "w-2.5 h-2.5 rounded-full bg-danger" }),
          h("span", null, "Inspection Failed")
        ),
        h("span", { className: "text-xs font-mono text-muted" }, "Error")
      ),
      h(
        "div",
        { className: "p-4 bg-ground/60 rounded-[8px] mb-6 border border-line" },
        h(
          "p",
          { className: "text-sm text-ink font-medium mb-1.5" },
          error || "An unexpected error occurred during threat inspection."
        ),
        url &&
          h(
            "p",
            { className: "text-xs text-muted font-mono break-all" },
            `Target Destination: ${url}`
          )
      ),
      h(
        "div",
        { className: "flex flex-col sm:flex-row items-stretch sm:items-center gap-3" },
        onRetry &&
          h(
            "button",
            {
              type: "button",
              onClick: onRetry,
              className:
                "py-2.5 px-6 bg-ink text-ground rounded-btn text-xs font-semibold hover:bg-ink/90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 transition-colors cursor-pointer text-center"
            },
            "Retry Scan"
          ),
        onScanAnother &&
          h(
            "button",
            {
              type: "button",
              onClick: onScanAnother,
              className:
                "py-2.5 px-4 bg-panel border border-line text-ink rounded-btn text-xs font-semibold hover:bg-ground hover:border-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 transition-colors cursor-pointer text-center"
            },
            "Scan Another"
          )
      )
    );
  }

  /**
   * Return clear, human-readable signal titles rather than raw technical IDs
   */
  function getSignalTitle(sig) {
    if (!sig) return "Security Signal";
    if (sig.title) return sig.title;
    const id = (sig.id || "").toLowerCase();

    if (id.startsWith("geo_location")) return "Server Location";
    if (id.startsWith("upi_")) {
      if (id === "upi_prefilled_amount") return "Pre-Filled Debit Amount";
      if (id === "upi_high_prefilled_amount") return "High Pre-Filled Payment Amount";
      if (id === "upi_payee_vpa_mismatch") return "Payee Name vs VPA Mismatch";
      if (id === "upi_collect_deception") return "Collect / Refund Deception Pattern";
      if (id === "upi_malformed_vpa") return "Malformed UPI Address";
      if (id === "upi_clean_structure") return "Verified UPI Structure";
      return "UPI Payment Signal";
    }
    if (id.startsWith("wifi_")) {
      if (id === "wifi_unencrypted") return "Unencrypted Open Wi-Fi";
      if (id === "wifi_wep_deprecated") return "Deprecated WEP Wi-Fi Encryption";
      if (id === "wifi_secure") return "Secure Encrypted Wi-Fi";
      return "Wi-Fi Security Signal";
    }
    if (id.startsWith("cdn_shield")) return "CDN Origin Cloaking";
    if (id.startsWith("proxy_vpn")) return "Anonymous Proxy / VPN";
    if (id.startsWith("ip_literal_host")) return "Direct IP Literal Destination";
    if (id.startsWith("fast_flux_dns")) return "Fast-Flux DNS Rotation";
    if (id.startsWith("ptr_contradiction")) return "Reverse DNS Contradiction";
    if (id.startsWith("verified_infrastructure")) return "Verified Infrastructure";
    if (id.startsWith("blocked_private_ip")) return "Private / Reserved IP Blocked";
    if (id.startsWith("abuseipdb")) return "AbuseIPDB Threat Reports";
    if (id.startsWith("brand_country") || id === "geo_brand_mismatch") return "Jurisdiction Mismatch";
    if (id === "multi_country_redirect_chain") return "Multi-Jurisdiction Redirect Chain";
    if (id.includes("urlhaus") && (id.includes("unavail") || id.includes("timeout"))) return "URLhaus Lookup Unavailable";
    if (id.includes("safebrowsing") && (id.includes("unavail") || id.includes("timeout"))) return "Google Safe Browsing Unavailable";
    if (id.includes("virustotal") && (id.includes("unavail") || id.includes("timeout"))) return "VirusTotal Lookup Unavailable";
    if (id.includes("openphish") && (id.includes("unavail") || id.includes("timeout"))) return "OpenPhish Feed Standby";
    if (id.includes("ssrf_blocked")) return "SSRF Loopback Blocked";
    if (id.includes("young_domain")) return "Recently Registered Domain";
    if (id.includes("shortener")) return "URL Shortener Detected";
    if (id.includes("lookalike")) return "Lookalike Brand Impersonation";
    if (id.includes("punycode")) return "Punycode Homograph Detected";
    if (id.includes("html_password_field")) return "Password Entry Field Detected";
    if (id.includes("cross_domain_form")) return "Cross-Domain Form Action";
    if (id.includes("hidden_iframe")) return "Hidden / Zero-Dimension Iframe";
    if (id.includes("obfuscated_js")) return "Obfuscated JavaScript Pattern";
    if (id.includes("title_brand_mismatch")) return "Brand Impersonation in Page Title";
    if (id.includes("tls_self_signed")) return "Self-Signed TLS Certificate";
    if (id.includes("tls_hostname_mismatch")) return "TLS Hostname Mismatch";
    if (id.includes("tls_expired")) return "Expired TLS Certificate";
    if (id.includes("tls_valid")) return "Valid TLS Encryption";
    if (id.includes("tls_invalid")) return "Invalid TLS Certificate";
    if (id.includes("at_delimiter")) return "Deceptive @ Credential Delimiter";
    if (id.includes("excessive_subdomains")) return "Excessive Subdomain Depth";
    if (id.includes("risky_tld")) return "Suspicious High-Risk TLD";

    if (sig.name) return sig.name;
    if (sig.id) {
      return sig.id.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
    }
    return sig.source || "Security Signal";
  }

  /**
   * Reusable ScanResultPanel Component
   * Full-width rectangular panel, expands naturally to its content, NO inner scrollbar.
   */
  function ScanResultPanel(props) {
    const { report, onScanAnother, onDownloadPdf, onCopyJson } = props;
    const [showAllSignals, setShowAllSignals] = useState(false);
    const [copiedIp, setCopiedIp] = useState(null);

    if (!report) return null;

    const verdictInfo = computeDisplayVerdict(report);
    const score = report.score !== undefined ? report.score : 0;

    const handleCopyIp = (ipToCopy) => {
      if (ipToCopy && ipToCopy !== "Unresolved" && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(ipToCopy);
        setCopiedIp(ipToCopy);
        setTimeout(() => {
          setCopiedIp((curr) => (curr === ipToCopy ? null : curr));
        }, 2000);
      }
    };

    // Build ordered hops list
    const hopsList = [];
    const chain = (report.redirect_chain && report.redirect_chain.chain) || [];
    if (chain.length > 0) {
      chain.forEach((hItem, idx) => {
        const isLast = idx === chain.length - 1;
        let hopDomain = hItem.domain;
        if (!hopDomain && hItem.url) {
          try { hopDomain = new URL(hItem.url).hostname; } catch(e) { hopDomain = ""; }
        }
        hopsList.push({
          num: String(idx + 1).padStart(2, "0"),
          url: hItem.url || report.url,
          domain: hopDomain || "Direct Host",
          statusCode: hItem.status_code !== undefined ? hItem.status_code : 200,
          reason: hItem.reason || (isLast ? "Terminal Destination" : "Redirect Hop"),
          isLast: isLast,
          isShortener: Boolean(hItem.is_shortener),
          danger: (isLast && report.status === "MALICIOUS") || (hItem.status_code >= 400 || hItem.status_code === 0)
        });
      });
    } else {
      const initialDomain = report.domain || report.host || (function() { try { return new URL(report.url).hostname; } catch(e) { return "Direct Host"; } })();
      hopsList.push({
        num: "01",
        url: report.url,
        domain: initialDomain,
        statusCode: 200,
        reason: "Direct Destination",
        isLast: !report.final_url || report.final_url === report.url,
        isShortener: false,
        danger: report.status === "MALICIOUS"
      });
      if (report.final_url && report.final_url !== report.url) {
        let finalDomain = report.domain || (function() { try { return new URL(report.final_url).hostname; } catch(e) { return ""; } })();
        hopsList.push({
          num: "02",
          url: report.final_url,
          domain: finalDomain || "Terminal Host",
          statusCode: 200,
          reason: "Final Terminal Destination",
          isLast: true,
          isShortener: false,
          danger: report.status === "MALICIOUS"
        });
      }
    }

    // Build sources checked array
    const sourcesChecked = report.sources_checked || {};
    let sourcesArray = [];
    if (Object.keys(sourcesChecked).length > 0) {
      sourcesArray = Object.keys(sourcesChecked).map((key) => {
        const src = sourcesChecked[key];
        return {
          key,
          name: src.name || key,
          status: src.status || (src.available ? "OK" : "UNAVAILABLE")
        };
      });
    } else {
      sourcesArray = [
        {
          name: "URLhaus Feed",
          status:
            report.threat_intel?.urlhaus?.status === "MALICIOUS"
              ? "FLAGGED"
              : report.threat_intel?.urlhaus?.status === "UNAVAILABLE"
              ? "UNAVAILABLE"
              : "OK"
        },
        {
          name: "VirusTotal",
          status:
            report.threat_intel?.virustotal?.status === "MALICIOUS"
              ? "FLAGGED"
              : report.threat_intel?.virustotal?.status === "UNAVAILABLE"
              ? "UNAVAILABLE"
              : "OK"
        },
        {
          name: "Safe Browsing",
          status:
            report.threat_intel?.safebrowsing?.status === "MALICIOUS"
              ? "FLAGGED"
              : report.threat_intel?.safebrowsing?.status === "UNAVAILABLE"
              ? "UNAVAILABLE"
              : "OK"
        },
        {
          name: "OpenPhish",
          status:
            report.threat_intel?.openphish?.status === "MALICIOUS"
              ? "FLAGGED"
              : report.threat_intel?.openphish?.status === "UNAVAILABLE"
              ? "UNAVAILABLE"
              : "OK"
        },
        {
          name: "DNS & Geo-IP",
          status: report.geo_ip && report.geo_ip.status !== "error" ? "OK" : "UNAVAILABLE"
        }
      ];
    }

    // Build and sort signals list
    let sortedSignals = [];
    if (report.signals && Array.isArray(report.signals) && report.signals.length > 0) {
      sortedSignals = [...report.signals].sort((a, b) => {
        const sevA = (a.severity || "info").toLowerCase();
        const sevB = (b.severity || "info").toLowerCase();
        const rankA = SEVERITY_ORDER[sevA] !== undefined ? SEVERITY_ORDER[sevA] : 1;
        const rankB = SEVERITY_ORDER[sevB] !== undefined ? SEVERITY_ORDER[sevB] : 1;
        if (rankB !== rankA) return rankB - rankA;
        const impA = Math.abs(a.score_impact || 0);
        const impB = Math.abs(b.score_impact || 0);
        return impB - impA;
      });
    } else if (report.reasons && Array.isArray(report.reasons) && report.reasons.length > 0) {
      sortedSignals = report.reasons.map((rStr, i) => ({
        id: `reason_${i + 1}`,
        source: "Threat Intelligence",
        severity: report.status === "MALICIOUS" ? "critical" : "info",
        score_impact: report.status === "MALICIOUS" ? 85 : 0,
        evidence: rStr
      }));
    }

    const displayedSignals = showAllSignals ? sortedSignals : sortedSignals.slice(0, 8);

    // Extract Network & Location data
    const network = report.network || {
      hosts: (report.geo_ip && report.geo_ip.ip) ? [{
        host: report.host || report.domain || "Destination Host",
        hop_index: 0,
        role: "final",
        ips: [{
          ip: report.geo_ip.ip,
          ptr: null,
          asn: report.geo_ip.asn || "N/A",
          org: report.geo_ip.org || report.geo_ip.isp || "Unknown",
          city: report.geo_ip.city || "Unknown",
          region: report.geo_ip.region || "Unknown",
          country: report.geo_ip.country || "Unknown",
          country_code: report.geo_ip.country_code || "UN",
          lat: report.geo_ip.latitude || 0,
          lon: report.geo_ip.longitude || 0,
          is_cdn: false,
          is_hosting: false,
          is_proxy_or_vpn: false,
          status: "ok"
        }],
        ttl: 300,
        a_record_count: 1
      }] : [],
      countries_in_path: (report.geo_ip && report.geo_ip.country_code) ? [report.geo_ip.country_code] : [],
      summary: (report.geo_ip && report.geo_ip.org) ? `Destination is hosted by ${report.geo_ip.org} (${report.geo_ip.city || ""}, ${report.geo_ip.country_code || ""}).` : "No network destination data available."
    };

    const networkRows = [];
    let detectedCdnName = null;

    (network.hosts || []).forEach((hItem, hIdx) => {
      const hopNum = String((hItem.hop_index !== undefined ? hItem.hop_index : hIdx) + 1).padStart(2, "0");
      const hostIps = hItem.ips && hItem.ips.length > 0 ? hItem.ips : [{
        ip: "Unresolved",
        ptr: null,
        asn: "N/A",
        org: "Host unresolvable",
        city: "Unknown",
        region: "Unknown",
        country: "Unknown",
        country_code: "UN",
        lat: 0,
        lon: 0,
        is_cdn: false,
        is_hosting: false,
        is_proxy_or_vpn: false,
        status: "unresolved"
      }];

      hostIps.forEach((ipData) => {
        if (ipData.is_cdn && ipData.cdn_name && !detectedCdnName) {
          detectedCdnName = ipData.cdn_name;
        }

        const latVal = typeof ipData.lat === "number" ? ipData.lat : 0;
        const lonVal = typeof ipData.lon === "number" ? ipData.lon : 0;

        networkRows.push({
          hopNum,
          host: hItem.host,
          role: hItem.role || "destination",
          ip: ipData.ip,
          ptr: ipData.ptr,
          asn: ipData.asn || "N/A",
          org: ipData.org || ipData.isp || "Unknown",
          city: ipData.city || "Unknown",
          region: ipData.region || "Unknown",
          country: ipData.country || "Unknown",
          country_code: ipData.country_code || "UN",
          lat: latVal,
          lon: lonVal,
          is_cdn: ipData.is_cdn,
          cdn_name: ipData.cdn_name,
          is_hosting: ipData.is_hosting,
          is_proxy_or_vpn: ipData.is_proxy_or_vpn,
          is_blocked: ipData.status === "blocked_private_ip"
        });
      });
    });

    const handleDownloadPdf = () => {
      if (typeof onDownloadPdf === "function") {
        onDownloadPdf(report);
      } else if (typeof window.downloadForensicReport === "function") {
        window.downloadForensicReport(report.url);
      }
    };

    const handleCopyJson = () => {
      if (typeof onCopyJson === "function") {
        onCopyJson(report);
      } else if (typeof window.copyReportJson === "function") {
        window.copyReportJson(report);
      }
    };

    const scanId =
      report.id ||
      `CS-${(report.url || "SCAN").replace(/^https?:\/\//i, "").slice(0, 8).replace(/[^a-zA-Z0-9]/g, "").toUpperCase() || "7E6E36"}`;

    return h(
      "div",
      {
        role: "region",
        "aria-label": "Scan result",
        className:
          "bg-panel rounded-[12px] border border-line p-6 sm:p-8 w-full max-w-[1240px] mx-auto text-ink shadow-sm"
      },
      // SECTION A: Summary Bar
      h(
        "div",
        { className: "pb-6 sm:pb-8 flex flex-col md:flex-row md:items-start justify-between gap-6" },
        // Left side: Verdict Label + Summary sentence + Mobile buttons
        h(
          "div",
          { className: "flex-grow min-w-0" },
          h(
            "div",
            { className: "flex items-center gap-2 mb-2 flex-wrap" },
            h(
              "span",
              { className: "text-xs uppercase tracking-wider text-muted font-semibold" },
              "Security Verdict"
            ),
            h(
              "span",
              {
                className: `text-[11px] font-mono font-bold px-2 py-0.5 rounded uppercase ${verdictInfo.badgeClass}`
              },
              verdictInfo.level
            ),
            report.payload_type &&
              h(
                "span",
                {
                  className: "text-[11px] font-mono font-bold px-2 py-0.5 rounded border border-line bg-ground text-ink uppercase"
                },
                report.payload_type === "UPI" ? "UPI Payment" : (report.payload_type === "URL" ? "Web Destination" : report.payload_type)
              )
          ),
          h(
            "h2",
            {
              className: `text-2xl sm:text-3xl lg:text-[32px] font-bold ${verdictInfo.colorClass} leading-tight mb-2 tracking-tight`
            },
            verdictInfo.verdictLabel
          ),
          h(
            "p",
            { className: "text-sm text-muted break-words leading-relaxed max-w-[680px]" },
            verdictInfo.summarySentence
          ),
          // Mobile Action Buttons (Stack full width on small screens)
          h(
            "div",
            { className: "mt-5 flex flex-col sm:flex-row items-stretch sm:items-center gap-3 sm:hidden" },
            h(
              "button",
              {
                type: "button",
                onClick: handleDownloadPdf,
                className:
                  "py-2.5 px-4 bg-ink text-ground rounded-btn text-xs font-semibold hover:bg-ink/90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 transition-colors cursor-pointer text-center"
              },
              "Download PDF Forensic Report"
            ),
            h(
              "button",
              {
                type: "button",
                onClick: handleCopyJson,
                className:
                  "py-2.5 px-4 bg-panel border border-ink text-ink rounded-btn text-xs font-semibold hover:bg-ground focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 transition-colors cursor-pointer text-center"
              },
              "Copy JSON"
            )
          )
        ),
        // Right side: Risk score + Confidence + Desktop buttons
        h(
          "div",
          { className: "flex flex-col items-start md:items-end shrink-0" },
          h(
            "div",
            { className: "text-left md:text-right mb-4" },
            h(
              "span",
              { className: "block text-xs uppercase tracking-wider text-muted font-semibold" },
              "Risk Score"
            ),
            h(
              "span",
              { className: "font-mono text-3xl sm:text-4xl font-bold text-ink leading-none mt-1 block" },
              `${score}/100`
            ),
            h(
              "span",
              { className: "text-xs font-mono text-muted mt-1 block" },
              `${verdictInfo.confidence}% Confidence Assessment`
            )
          ),
          // Desktop Action Buttons
          h(
            "div",
            { className: "hidden sm:flex items-center gap-3" },
            h(
              "button",
              {
                type: "button",
                onClick: handleDownloadPdf,
                className:
                  "py-2.5 px-4 bg-ink text-ground rounded-btn text-xs font-semibold hover:bg-ink/90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 transition-colors cursor-pointer text-center"
              },
              "Download PDF Forensic Report"
            ),
            h(
              "button",
              {
                type: "button",
                onClick: handleCopyJson,
                className:
                  "py-2.5 px-4 bg-panel border border-ink text-ink rounded-btn text-xs font-semibold hover:bg-ground focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 transition-colors cursor-pointer text-center"
              },
              "Copy JSON"
            )
          )
        )
      ),

      // SECTION B: Two-Column Row (Stacks on mobile)
      h(
        "div",
        {
          className:
            "pt-6 sm:pt-8 pb-6 sm:pb-8 border-t border-line grid grid-cols-1 md:grid-cols-2 gap-8 lg:gap-12"
        },
        // LEFT: "UPI Payment Parameters" OR "Redirect path"
        report.payload_type === "UPI" && report.upi_details
          ? h(
              "div",
              { className: "flex flex-col min-w-0" },
              h(
                "div",
                { className: "flex items-center justify-between mb-3" },
                h(
                  "span",
                  { className: "text-xs uppercase tracking-wider text-muted font-semibold" },
                  "UPI Payment Parameters"
                ),
                h(
                  "span",
                  { className: "text-xs font-mono text-muted" },
                  report.upi_details.cu || "INR"
                )
              ),
              h(
                "div",
                { className: "space-y-2.5 font-mono text-xs rounded-input bg-ground/40 border border-line p-4" },
                h(
                  "div",
                  { className: "flex items-center justify-between pb-2 border-b border-line/60" },
                  h("span", { className: "text-muted font-sans" }, "Payee Name (pn):"),
                  h("span", { className: "text-ink font-semibold" }, report.upi_details.pn || "Not specified")
                ),
                h(
                  "div",
                  { className: "flex items-center justify-between pb-2 border-b border-line/60" },
                  h("span", { className: "text-muted font-sans" }, "Payee VPA (pa):"),
                  h(
                    "span",
                    { className: "text-ink font-bold flex items-center gap-2" },
                    report.upi_details.pa,
                    report.upi_details.pa && h(
                      "button",
                      {
                        type: "button",
                        onClick: () => handleCopyIp(report.upi_details.pa),
                        className: "px-1.5 py-0.5 text-[10px] font-mono border border-line rounded hover:border-ink bg-panel transition-colors cursor-pointer text-muted hover:text-ink"
                      },
                      copiedIp === report.upi_details.pa ? "Copied" : "Copy"
                    )
                  )
                ),
                h(
                  "div",
                  { className: "flex items-center justify-between pb-2 border-b border-line/60" },
                  h("span", { className: "text-muted font-sans" }, "Pre-filled Amount (am):"),
                  h(
                    "span",
                    { className: `font-bold ${report.upi_details.am ? "text-danger" : "text-safe"}` },
                    report.upi_details.am ? `₹${Number(report.upi_details.am).toLocaleString()} ${report.upi_details.cu || "INR"}` : "None (User-Specified)"
                  )
                ),
                h(
                  "div",
                  { className: "flex items-center justify-between" },
                  h("span", { className: "text-muted font-sans" }, "Purpose / Note (tn):"),
                  h("span", { className: "text-ink truncate max-w-[200px]" }, report.upi_details.tn || "None")
                )
              )
            )
          : h(
              "div",
              { className: "flex flex-col min-w-0" },
              h(
                "div",
                { className: "flex items-center justify-between mb-3" },
                h(
                  "span",
                  { className: "text-xs uppercase tracking-wider text-muted font-semibold" },
                  "Redirect path"
                ),
                h(
                  "span",
                  { className: "text-xs font-mono text-muted" },
                  `${hopsList.length} hop${hopsList.length === 1 ? "" : "s"}`
                )
              ),
              h(
                "div",
                { className: "flex flex-col divide-y divide-line/60" },
                hopsList.map((hop, idx) => {
                  let statusBadgeClass = "border-line text-ink bg-ground/50";
                  if (hop.statusCode >= 300 && hop.statusCode < 400) {
                    statusBadgeClass = "border-suspicious text-suspicious bg-suspicious/5";
                  } else if (hop.statusCode >= 400 || hop.statusCode === 0) {
                    statusBadgeClass = "border-danger text-danger bg-danger/5";
                  } else if (hop.statusCode === 200) {
                    statusBadgeClass = "border-safe text-safe bg-safe/5";
                  }
                  return h(
                    "div",
                    { key: idx, className: "py-3 first:pt-0 last:pb-0 flex items-start gap-3" },
                    h("span", { className: "font-mono text-xs text-muted font-bold shrink-0 pt-0.5" }, hop.num),
                    h(
                      "div",
                      { className: "flex-grow min-w-0 space-y-1" },
                      h(
                        "div",
                        {
                          className: `font-mono text-xs sm:text-sm font-medium break-all ${hop.danger ? "text-danger font-bold" : "text-ink"}`
                        },
                        hop.url
                      ),
                      h(
                        "div",
                        { className: "flex items-center gap-2 flex-wrap text-xs font-mono" },
                        h(
                          "span",
                          { className: `text-[10px] font-bold px-1.5 py-0.5 rounded border ${statusBadgeClass}` },
                          hop.statusCode ? `HTTP ${hop.statusCode}` : "ERR"
                        ),
                        h(
                          "span",
                          { className: "text-[11px] font-semibold text-muted bg-panel border border-line px-1.5 py-0.5 rounded truncate max-w-[200px]" },
                          hop.domain
                        ),
                        hop.isShortener && h(
                          "span",
                          { className: "text-[10px] font-bold px-1.5 py-0.5 rounded border border-suspicious text-suspicious bg-suspicious/5" },
                          "SHORTENER"
                        ),
                        h("span", { className: "text-muted text-[11px]" }, hop.reason)
                      )
                    )
                  );
                })
              ),
              report.final_url &&
                h(
                  "div",
                  { className: "mt-3 pt-3 border-t border-line/60 flex items-center justify-between gap-2 text-xs font-mono text-muted" },
                  h("span", { className: "font-semibold text-ink uppercase tracking-wider text-[11px]" }, "Final Destination:"),
                  h("span", { className: "truncate max-w-[280px] text-ink font-medium" }, report.final_url)
                )
            ),
        // RIGHT: "Sources checked"
        h(
          "div",
          { className: "flex flex-col min-w-0" },
          h(
            "div",
            { className: "flex items-center justify-between mb-3" },
            h(
              "span",
              { className: "text-xs uppercase tracking-wider text-muted font-semibold" },
              "Sources checked"
            ),
            h(
              "span",
              { className: "text-xs font-mono text-muted" },
              `${sourcesArray.length} inspected`
            )
          ),
          h(
            "div",
            { className: "grid grid-cols-1 sm:grid-cols-2 gap-2.5" },
            sourcesArray.map((s, idx) => {
              let statusText = (s.status || "OK").toUpperCase();
              let statusBadgeClass = "text-safe font-bold";
              if (statusText === "FLAGGED" || statusText === "MALICIOUS") {
                statusText = "FLAGGED";
                statusBadgeClass = "text-danger font-bold";
              } else if (statusText === "UNAVAILABLE") {
                statusBadgeClass = "text-muted font-medium";
              } else if (statusText === "SKIPPED") {
                statusBadgeClass = "text-muted font-medium";
              }
              return h(
                "div",
                {
                  key: idx,
                  className:
                    "p-2.5 rounded-[8px] bg-ground/50 border border-line flex items-center justify-between gap-2 text-xs font-mono"
                },
                h("span", { className: "text-ink truncate" }, s.name),
                h(
                  "span",
                  { className: `text-[11px] ${statusBadgeClass} shrink-0` },
                  statusText
                )
              );
            })
          )
        )
      ),

      // SECTION C: "Network & Location" (Between Redirect Path/Sources and Signals)
      h(
        "div",
        { className: "pt-6 sm:pt-8 pb-6 sm:pb-8 border-t border-line" },
        // Section Header Row
        h(
          "div",
          { className: "flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3" },
          h(
            "div",
            { className: "flex items-center gap-2 flex-wrap" },
            h(
              "span",
              { className: "text-xs uppercase tracking-wider text-muted font-semibold" },
              "Network & Location"
            ),
            network.countries_in_path && network.countries_in_path.length > 0 &&
              h(
                "div",
                { className: "flex items-center gap-1.5 flex-wrap" },
                network.countries_in_path.map((cc, cIdx) =>
                  h(
                    "span",
                    {
                      key: cIdx,
                      className:
                        "text-[10px] font-mono font-bold px-2 py-0.5 rounded-chip border border-line bg-ground text-ink uppercase"
                    },
                    cc
                  )
                )
              )
          ),
          detectedCdnName &&
            h(
              "span",
              {
                className:
                  "text-[11px] font-mono font-semibold px-2 py-0.5 rounded-chip border border-line bg-panel text-ink self-start sm:self-auto"
              },
              `Behind CDN: ${detectedCdnName}`
            )
        ),

        // One-line summary
        h(
          "p",
          { className: "text-sm text-ink font-medium mb-4 leading-relaxed max-w-[840px]" },
          network.summary || "Destination infrastructure and server location telemetry."
        ),

        // Table or Empty State
        networkRows.length > 0
          ? h(
              "div",
              { className: "w-full" },
              // Desktop Table
              h(
                "div",
                { className: "hidden md:block overflow-x-auto rounded-input border border-line bg-panel" },
                h(
                  "table",
                  { className: "w-full text-left text-xs border-collapse", "aria-label": "Server network and location details" },
                  h(
                    "thead",
                    { className: "border-b border-line bg-ground/50 text-muted font-semibold" },
                    h(
                      "tr",
                      null,
                      h("th", { className: "py-2.5 px-3 font-mono font-bold" }, "Hop"),
                      h("th", { className: "py-2.5 px-3" }, "Host"),
                      h("th", { className: "py-2.5 px-3" }, "IP Address"),
                      h("th", { className: "py-2.5 px-3" }, "Reverse DNS (PTR)"),
                      h("th", { className: "py-2.5 px-3" }, "ASN & Organisation"),
                      h("th", { className: "py-2.5 px-3" }, "Location"),
                      h("th", { className: "py-2.5 px-3" }, "Flags")
                    )
                  ),
                  h(
                    "tbody",
                    { className: "divide-y divide-line/60 font-mono" },
                    networkRows.map((row, rIdx) => {
                      const flags = [];
                      if (row.is_blocked) flags.push({ label: "PRIVATE-BLOCKED", badgeClass: "border-danger text-danger bg-danger/5" });
                      if (row.is_cdn) flags.push({ label: "CDN", badgeClass: "border-line text-ink bg-ground" });
                      if (row.is_hosting) flags.push({ label: "HOSTING", badgeClass: "border-line text-muted bg-ground" });
                      if (row.is_proxy_or_vpn) flags.push({ label: "PROXY/VPN", badgeClass: "border-suspicious text-suspicious bg-suspicious/5" });

                      const locText = row.city !== "Unknown" ? `${row.city}, ${row.country_code}` : (row.country !== "Unknown" ? `${row.country} (${row.country_code})` : "Unknown");
                      const coordText = (row.lat !== 0 || row.lon !== 0) ? `(${row.lat.toFixed(2)}, ${row.lon.toFixed(2)})` : "";

                      return h(
                        "tr",
                        { key: rIdx, className: "hover:bg-ground/30 transition-colors" },
                        h("td", { className: "py-2.5 px-3 text-muted font-bold whitespace-nowrap" }, row.hopNum),
                        h("td", { className: "py-2.5 px-3 text-ink font-medium break-all max-w-[180px]" }, row.host),
                        h(
                          "td",
                          { className: "py-2.5 px-3 text-ink font-medium whitespace-nowrap" },
                          h("span", null, row.ip),
                          row.ip !== "Unresolved" && h(
                            "button",
                            {
                              type: "button",
                              onClick: () => handleCopyIp(row.ip),
                              className:
                                "ml-2 px-1.5 py-0.5 text-[10px] font-mono border border-line rounded hover:border-ink bg-ground/60 transition-colors cursor-pointer text-muted hover:text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-1"
                            },
                            copiedIp === row.ip ? "Copied" : "Copy"
                          )
                        ),
                        h("td", { className: "py-2.5 px-3 text-muted text-xs break-all max-w-[180px]" }, row.ptr || "None"),
                        h(
                          "td",
                          { className: "py-2.5 px-3 max-w-[200px]" },
                          h("div", { className: "text-ink font-semibold" }, row.asn),
                          h("div", { className: "text-muted text-[11px] font-sans truncate" }, row.org)
                        ),
                        h(
                          "td",
                          { className: "py-2.5 px-3 max-w-[180px]" },
                          h("div", { className: "text-ink font-sans" }, locText),
                          coordText && h("div", { className: "text-muted text-[11px]" }, coordText)
                        ),
                        h(
                          "td",
                          { className: "py-2.5 px-3 whitespace-nowrap" },
                          h(
                            "div",
                            { className: "flex items-center gap-1.5 flex-wrap" },
                            flags.length > 0
                              ? flags.map((fl, fIdx) => h("span", { key: fIdx, className: `text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${fl.badgeClass}` }, fl.label))
                              : h("span", { className: "text-muted text-[11px] font-sans" }, "Standard")
                          )
                        )
                      );
                    })
                  )
                )
              ),

              // Mobile Stacked Cards
              h(
                "div",
                { className: "block md:hidden space-y-3" },
                networkRows.map((row, rIdx) => {
                  const flags = [];
                  if (row.is_blocked) flags.push({ label: "PRIVATE-BLOCKED", badgeClass: "border-danger text-danger bg-danger/5" });
                  if (row.is_cdn) flags.push({ label: "CDN", badgeClass: "border-line text-ink bg-ground" });
                  if (row.is_hosting) flags.push({ label: "HOSTING", badgeClass: "border-line text-muted bg-ground" });
                  if (row.is_proxy_or_vpn) flags.push({ label: "PROXY/VPN", badgeClass: "border-suspicious text-suspicious bg-suspicious/5" });

                  const locText = row.city !== "Unknown" ? `${row.city}, ${row.country_code}` : (row.country !== "Unknown" ? `${row.country} (${row.country_code})` : "Unknown");
                  const coordText = (row.lat !== 0 || row.lon !== 0) ? `(${row.lat.toFixed(2)}, ${row.lon.toFixed(2)})` : "";

                  return h(
                    "div",
                    { key: rIdx, className: "p-4 rounded-input bg-ground/40 border border-line space-y-2 text-xs" },
                    h(
                      "div",
                      { className: "flex items-center justify-between pb-2 border-b border-line/60" },
                      h("span", { className: "font-mono font-bold text-muted" }, `Hop ${row.hopNum}`),
                      h(
                        "div",
                        { className: "flex items-center gap-1.5 flex-wrap" },
                        flags.map((fl, fIdx) => h("span", { key: fIdx, className: `text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border uppercase ${fl.badgeClass}` }, fl.label))
                      )
                    ),
                    h("div", { className: "font-mono text-ink font-semibold break-all" }, row.host),
                    h(
                      "div",
                      { className: "flex items-center justify-between pt-1" },
                      h("span", { className: "text-muted font-sans" }, "IP Address:"),
                      h(
                        "span",
                        { className: "font-mono text-ink font-medium flex items-center gap-2" },
                        row.ip,
                        row.ip !== "Unresolved" && h(
                          "button",
                          {
                            type: "button",
                            onClick: () => handleCopyIp(row.ip),
                            className: "px-1.5 py-0.5 text-[10px] font-mono border border-line rounded hover:border-ink bg-panel transition-colors cursor-pointer text-muted hover:text-ink"
                          },
                          copiedIp === row.ip ? "Copied" : "Copy"
                        )
                      )
                    ),
                    row.ptr && h(
                      "div",
                      { className: "flex items-center justify-between text-muted" },
                      h("span", { className: "font-sans" }, "Reverse DNS:"),
                      h("span", { className: "font-mono break-all text-right max-w-[200px]" }, row.ptr)
                    ),
                    h(
                      "div",
                      { className: "flex items-center justify-between text-muted" },
                      h("span", { className: "font-sans" }, "ASN & Org:"),
                      h("span", { className: "font-mono text-right max-w-[200px]" }, `${row.asn} ${row.org}`)
                    ),
                    h(
                      "div",
                      { className: "flex items-center justify-between text-muted" },
                      h("span", { className: "font-sans" }, "Location:"),
                      h("span", { className: "font-sans text-ink text-right" }, `${locText} ${coordText}`)
                    )
                  );
                })
              )
            )
          : h(
              "div",
              { className: "p-4 rounded-input bg-ground/30 border border-line text-xs font-mono text-muted text-center" },
              (report.url && !/^https?:\/\//i.test(report.url)) ? "No network destination to trace." : "No network data available for this scan."
            ),

        // Note D under section (sits exactly 16px below table)
        h(
          "p",
          { className: "text-xs text-muted mt-4 font-mono leading-relaxed" },
          "Locations come from IP geolocation databases and are approximate (usually city or region level). For sites behind a CDN, the location shown is the CDN edge, not the real server."
        )
      ),

      // SECTION D: "Why this score" (Full width list, expanded, NO inner scrollbar)
      h(
        "div",
        { className: "pt-6 sm:pt-8 pb-6 sm:pb-8 border-t border-line" },
        h(
          "div",
          { className: "flex items-center justify-between mb-4" },
          h(
            "span",
            { className: "text-xs uppercase tracking-wider text-muted font-semibold" },
            "Why this score / Signals"
          ),
          h(
            "span",
            { className: "text-xs font-mono text-muted" },
            `${sortedSignals.length} signal${sortedSignals.length === 1 ? "" : "s"}`
          )
        ),
        h(
          "div",
          {
            className:
              "flex flex-col divide-y divide-line/60 bg-ground/40 rounded-input p-4 border border-line"
          },
          displayedSignals.length > 0
            ? displayedSignals.map((sig, idx) => {
                const sev = (sig.severity || "info").toLowerCase();
                let sevText = "INFO";
                let sevBadge = "border border-line text-muted bg-panel";
                if (sev === "critical" || sev === "high" || sev === "danger") {
                  sevText = "HIGH";
                  sevBadge = "border border-danger text-danger bg-danger/5";
                } else if (sev === "warning" || sev === "suspicious" || sev === "medium") {
                  sevText = "MEDIUM";
                  sevBadge = "border border-suspicious text-suspicious bg-suspicious/5";
                } else if (sev === "low") {
                  sevText = "LOW";
                  sevBadge = "border border-line text-muted bg-panel";
                } else if (sev === "safe") {
                  sevText = "SAFE";
                  sevBadge = "border border-safe text-safe bg-safe/5";
                }

                const impact = sig.score_impact !== undefined ? sig.score_impact : 0;
                const impactStr = impact > 0 ? `+${impact}` : impact < 0 ? `${impact}` : `0`;
                const impactClass =
                  impact > 0
                    ? "text-danger"
                    : impact < 0
                    ? "text-safe"
                    : "text-muted";

                return h(
                  "div",
                  {
                    key: idx,
                    className: "py-3 first:pt-0 last:pb-0 flex items-start justify-between gap-4"
                  },
                  h(
                    "div",
                    { className: "flex items-start gap-3 min-w-0 flex-grow" },
                    h(
                      "span",
                      {
                        className: `font-mono font-semibold px-2 py-0.5 rounded text-[10px] uppercase border shrink-0 pt-0.5 ${sevBadge}`
                      },
                      sevText
                    ),
                    h(
                      "div",
                      { className: "min-w-0 flex-grow" },
                      h(
                        "div",
                        { className: "flex items-center gap-2 flex-wrap" },
                        h(
                          "span",
                          { className: "text-xs font-bold text-ink" },
                          getSignalTitle(sig)
                        ),
                        sig.source &&
                          h(
                            "span",
                            { className: "text-[11px] font-mono text-muted" },
                            `[${sig.source}]`
                          )
                      ),
                      h(
                        "p",
                        {
                          className:
                            "text-xs text-muted leading-relaxed font-mono mt-1 break-words"
                        },
                        sig.evidence || sig.description || ""
                      )
                    )
                  ),
                  h(
                    "span",
                    { className: `font-mono text-xs font-bold shrink-0 pt-0.5 ${impactClass}` },
                    impactStr
                  )
                );
              })
            : h(
                "div",
                { className: "py-2 text-xs text-muted font-mono" },
                "No threat signals detected. Destination link verified clean across all checks."
              )
        ),
        // Toggle if > 8 signals
        sortedSignals.length > 8 &&
          h(
            "div",
            { className: "mt-4 text-center" },
            h(
              "button",
              {
                type: "button",
                onClick: () => setShowAllSignals(!showAllSignals),
                className:
                  "px-4 py-1.5 text-xs font-semibold text-muted hover:text-ink hover:border-ink bg-panel border border-line rounded-btn transition-colors cursor-pointer focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2"
              },
              showAllSignals
                ? "Show fewer signals"
                : `Show all ${sortedSignals.length} signals`
            )
          )
      ),

      // SECTION D: Footer Row
      h(
        "div",
        {
          className:
            "pt-6 border-t border-line flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-xs font-mono text-muted"
        },
        h(
          "div",
          { className: "flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 break-all" },
          h("span", null, `Scanned: ${report.time || new Date().toISOString().replace("T", " ").slice(0, 19)}`),
          h("span", { className: "hidden sm:inline" }, "•"),
          h("span", null, `ID: ${scanId}`)
        ),
        h(
          "button",
          {
            type: "button",
            onClick: onScanAnother,
            className:
              "px-4 py-2 bg-panel border border-line text-ink rounded-btn text-xs font-semibold hover:bg-ground hover:border-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 transition-colors cursor-pointer w-full sm:w-auto text-center"
          },
          "Scan another"
        )
      )
    );
  }

  /**
   * Container for managing state rendering and smooth scrollIntoView
   */
  function ScanResultContainer(props) {
    const { state, report, error, url, onRetry, onScanAnother, onDownloadPdf, onCopyJson } = props;
    const containerRef = useRef(null);

    useEffect(() => {
      if (state === "loading" || state === "success" || state === "error") {
        if (containerRef.current) {
          containerRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    }, [state]);

    if (state === "loading") {
      return h(
        "div",
        { ref: containerRef, className: "w-full scroll-mt-24" },
        h(ScanResultSkeleton, { url })
      );
    }
    if (state === "error") {
      return h(
        "div",
        { ref: containerRef, className: "w-full scroll-mt-24" },
        h(ScanResultError, { error, url, onRetry, onScanAnother })
      );
    }
    if (state === "success" && report) {
      return h(
        "div",
        { ref: containerRef, className: "w-full scroll-mt-24" },
        h(ScanResultPanel, { report, onScanAnother, onDownloadPdf, onCopyJson })
      );
    }
    return null;
  }

  /**
   * Primary React URL Scanner Page Component
   */
  function URLScannerComponent() {
    const [url, setUrl] = useState("");
    const [scanState, setScanState] = useState("idle"); // idle, loading, success, error
    const [error, setError] = useState(null);
    const [report, setReport] = useState(null);
    const abortControllerRef = useRef(null);

    // Support pending scans passed from homepage
    useEffect(() => {
      try {
        const pending = sessionStorage.getItem("pendingScanUrl");
        if (pending) {
          sessionStorage.removeItem("pendingScanUrl");
          setUrl(pending);
          handleScan(pending);
        }
      } catch (err) {}
    }, []);

    // Expose preset loader so template chips work
    useEffect(() => {
      window.triggerUrlScan = (targetUrl) => {
        setUrl(targetUrl);
        handleScan(targetUrl);
      };
      window.loadScannerPreset = window.triggerUrlScan;
      return () => {
        delete window.triggerUrlScan;
      };
    }, []);

    const handleScan = async (targetUrl) => {
      const scanUrl = (targetUrl !== undefined ? targetUrl : url).trim();

      if (!scanUrl) {
        setError("Please enter a destination URL to inspect.");
        setScanState("error");
        setReport(null);
        return;
      }

      if (!/^https?:\/\//i.test(scanUrl)) {
        setError("Invalid link schema: Only standard web links (http:// or https://) are supported.");
        setScanState("error");
        setReport(null);
        return;
      }

      // Check authentication gate
      if (window.CYBER_AUTH && !window.CYBER_AUTH.isAuthenticated) {
        window.location.href = (window.CYBER_AUTH && window.CYBER_AUTH.loginUrl) || "/login";
        return;
      }

      // Stale result fix (3a): IMMEDIATELY clear previous report and error
      setReport(null);
      setError(null);
      setScanState("loading");

      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      const controller = new AbortController();
      abortControllerRef.current = controller;
      const timeoutId = setTimeout(() => controller.abort(), 15000);

      try {
        const response = await fetch("/check-url", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
          },
          body: JSON.stringify({ url: scanUrl }),
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          let msg = "Threat inspection failed.";
          try {
            const errJson = await response.json();
            msg = errJson.error || msg;
          } catch (e) {}
          throw new Error(msg);
        }

        const data = await response.json();
        setReport(data);
        setError(null);
        setScanState("success");

        try {
          sessionStorage.setItem("guardResult", JSON.stringify(data));
        } catch (e) {}
      } catch (err) {
        clearTimeout(timeoutId);
        setReport(null);
        setScanState("error");
        if (err.name === "AbortError") {
          setError(
            "Request timed out: Live threat intelligence feeds took longer than 15 seconds to reply. Please check your network connection and retry."
          );
        } else {
          setError(err.message || "An unexpected error occurred during threat inspection.");
        }
      }
    };

    const handleScanAnother = () => {
      setUrl("");
      setReport(null);
      setError(null);
      setScanState("idle");
      const inputEl = document.getElementById("urlInput");
      if (inputEl) {
        inputEl.focus();
      }
    };

    return h(
      "div",
      { className: "w-full max-w-[1240px] mx-auto" },
      // TOP SECTION: Full-Width Input Block
      h(
        "div",
        { className: "pt-8 lg:pt-14 pb-8 border-b border-line/60" },
        h(
          "span",
          { className: "text-xs font-semibold uppercase tracking-wider text-muted mb-3 block font-mono" },
          "URL scanner"
        ),
        h(
          "h1",
          {
            className:
              "text-[36px] sm:text-[46px] lg:text-[54px] font-bold text-ink leading-[1.05] tracking-tight mb-4"
          },
          "Know where a link goes before you tap it."
        ),
        h(
          "p",
          { className: "text-[16px] sm:text-[18px] text-muted max-w-[620px] leading-relaxed mb-6" },
          "We follow redirects and query live threat feeds in an isolated sandbox pipeline without ever opening the destination page on your device."
        ),

        // Input Form
        h(
          "form",
          {
            className: "w-full max-w-[760px]",
            onSubmit: (e) => {
              e.preventDefault();
              handleScan(url);
            }
          },
          h(
            "label",
            { htmlFor: "urlInput", className: "block text-sm font-semibold text-ink mb-2" },
            "Destination URL"
          ),
          h(
            "div",
            {
              className:
                "flex items-stretch bg-panel border-[1.5px] border-ink rounded-input overflow-hidden shadow-sm focus-within:ring-2 focus-within:ring-ink"
            },
            h("input", {
              id: "urlInput",
              type: "url",
              value: url,
              onChange: (e) => setUrl(e.target.value),
              placeholder: "https://example.com/login",
              autoComplete: "url",
              required: true,
              className:
                "flex-grow bg-transparent text-ink font-mono text-[15px] px-4 py-3.5 focus:outline-none min-w-0"
            }),
            h(
              "button",
              {
                id: "checkBtn",
                type: "submit",
                disabled: scanState === "loading",
                className:
                  "bg-ink text-ground font-medium text-[15px] px-6 py-3.5 hover:bg-ink/90 transition-colors shrink-0 cursor-pointer disabled:opacity-50"
              },
              scanState === "loading" ? "Analyzing..." : "Check link"
            )
          )
        ),

        h(
          "p",
          { className: "text-xs text-muted mt-4" },
          "Never paste URLs containing passwords or personal info."
        )
      ),

      // RESULT SECTION: Rendered Underneath Full Width
      scanState !== "idle" &&
        h(
          "div",
          { className: "mt-8 sm:mt-10 w-full" },
          h(ScanResultContainer, {
            state: scanState,
            report,
            error,
            url,
            onRetry: () => handleScan(url),
            onScanAnother: handleScanAnother
          })
        ),

      // BOTTOM FEATURE STRIP
      h(
        "section",
        {
          className:
            "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 pt-16 mt-20 border-t border-line"
        },
        h(
          "div",
          { className: "pt-4 border-t-2 border-ink" },
          h("div", { className: "font-mono text-sm text-muted font-semibold mb-2" }, "01"),
          h("h3", { className: "text-[20px] font-bold text-ink mb-2 leading-snug" },           "URL scanner"),          h(
            "p",
            { className: "text-[15px] text-muted leading-relaxed mb-4" },
            "Inspect complete destinations with AI phishing score, URLhaus feed matching, Geo-IP, and redirect tracing."
          ),
          h(
            "a",
            {
              href: "/scanner",
              className:
                "text-sm font-semibold text-ink hover:underline inline-flex items-center gap-1"
            },
            "Explore Scanner →"
          )
        ),
        h(
          "div",
          { className: "pt-4 border-t-2 border-ink" },
          h("div", { className: "font-mono text-sm text-muted font-semibold mb-2" }, "02"),
          h("h3", { className: "text-[20px] font-bold text-ink mb-2 leading-snug" }, "QR scanner"),
          h(
            "p",
            { className: "text-[15px] text-muted leading-relaxed mb-4" },
            "Scan physical QR codes via live webcam or upload images to decode destinations and verify threat indicators."
          ),
          h(
            "a",
            {
              href: "/qr-scanner",
              className:
                "text-sm font-semibold text-ink hover:underline inline-flex items-center gap-1"
            },
            "Explore QR Tool →"
          )
        ),
        h(
          "div",
          { className: "pt-4 border-t-2 border-ink" },
          h("div", { className: "font-mono text-sm text-muted font-semibold mb-2" }, "03"),
          h("h3", { className: "text-[20px] font-bold text-ink mb-2 leading-snug" }, "Email analyzer"),
          h(
            "p",
            { className: "text-[15px] text-muted leading-relaxed mb-4" },
            "Investigate email sender spoofing, validate SPF/DKIM/DMARC headers, and analyze phishing urgency NLP."
          ),
          h(
            "a",
            {
              href: "/email-analyzer",
              className:
                "text-sm font-semibold text-ink hover:underline inline-flex items-center gap-1"
            },
            "Explore Forensics →"
          )
        ),
        h(
          "div",
          { className: "pt-4 border-t-2 border-ink" },
          h("div", { className: "font-mono text-sm text-muted font-semibold mb-2" }, "04"),
          h("h3", { className: "text-[20px] font-bold text-ink mb-2 leading-snug" }, "Scan history"),
          h(
            "p",
            { className: "text-[15px] text-muted leading-relaxed mb-4" },
            "Comprehensive security audit trails for authenticated sessions with instant PDF forensic reports."
          ),
          h(
            "a",
            {
              href: "/dashboard",
              className:
                "text-sm font-semibold text-ink hover:underline inline-flex items-center gap-1"
            },
            "Open History →"
          )
        )
      )
    );
  }

  // Root registry for mounting into containers
  const rootsMap = new Map();

  function renderScanResult(container, props) {
    if (!container) return;
    let root = rootsMap.get(container);
    if (!root) {
      root = ReactDOM.createRoot(container);
      rootsMap.set(container, root);
    }
    root.render(h(ScanResultContainer, props));
  }

  window.CyberScapeReact = {
    ScanResultPanel,
    ScanResultSkeleton,
    ScanResultError,
    ScanResultContainer,
    URLScannerComponent,
    computeDisplayVerdict,
    renderScanResult,
    mountScannerApp: function (containerId) {
      const container = document.getElementById(containerId);
      if (container && ReactDOM.createRoot) {
        let root = rootsMap.get(container);
        if (!root) {
          root = ReactDOM.createRoot(container);
          rootsMap.set(container, root);
        }
        root.render(h(URLScannerComponent));
      }
    }
  };
})();

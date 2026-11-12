# CyberScape API Keys & Threat Intelligence Setup

This guide details the configuration of external threat intelligence providers, geolocation services, and privacy practices in CyberScape.

---

## 1. Strict Privacy & User IP Policy

> **CRITICAL PRIVACY GUARANTEE:**
> CyberScape traces only the **destination servers** a link, QR code, or email route points to. CyberScape **NEVER** looks up, logs, stores, or transmits the IP address or geographic location of the user accessing or operating the CyberScape platform.
>
> All geolocation queries are performed strictly on resolved destination web hosts, redirect hops, and email relay headers.

---

## 2. Geolocation & Network Intelligence Services (Optional)

CyberScape operates multi-tier geolocation with automatic fallbacks so that scans never fail if an external API is down or unconfigured.

### A. Offline MaxMind GeoLite2 (.mmdb) — Best Performance & Zero Data Leakage
- **Benefit:** Completely offline, no rate limits, zero external network calls.
- **Setup:**
  1. Register for a free MaxMind account at [https://www.maxmind.com/](https://www.maxmind.com/).
  2. Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
  3. Place them in a folder (e.g., `data/geolite2/`).
  4. In your `.env` file, specify:
     ```bash
     GEOLITE2_DB_PATH=data/geolite2
     ```
  5. Install `maxminddb`:
     ```bash
     pip install maxminddb
     ```

### B. ipwho.is (Primary Online Fallback)
- **Benefit:** Free HTTPS endpoint, 10,000 queries/month, no API key required.
- Automatically used as the primary online fallback when no local MaxMind database is detected.

### C. ipinfo.io (Secondary Online Fallback)
- **Benefit:** High-speed HTTPS endpoint (50,000 queries/month free tier).
- **Setup:**
  1. Create a free account at [https://ipinfo.io/](https://ipinfo.io/).
  2. Copy your API access token to `.env`:
     ```bash
     IPINFO_TOKEN=your_token_here
     ```

### D. AbuseIPDB (Optional IP Reputation Feed)
- **Benefit:** Flags malicious IPs and botnet command-and-control servers with confidence scoring.
- **Setup:**
  1. Register at [https://www.abuseipdb.com/](https://www.abuseipdb.com/).
  2. Copy your API key to `.env`:
     ```bash
     ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
     ```

---

## 3. Threat Intelligence Feed Keys (Optional)

| Service | Environment Variable | Free Tier Policy |
| :--- | :--- | :--- |
| **VirusTotal v3** | `VIRUSTOTAL_API_KEY` | 500 requests/day, 4/min |
| **Google Safe Browsing v4** | `GOOGLE_SAFEBROWSING_API_KEY` | 10,000 requests/day |
| **URLhaus Feed** | `URLHAUS_API_KEY` | Public API works with or without key |
| **OpenPhish Feed** | *(Built-in)* | Local hourly feed cache |

---

## 4. SSRF & DNS Rebinding Security

To protect internal infrastructure and prevent server-side request forgery (SSRF):
1. **Single Resolution:** Destination hosts are resolved once; the resolved IP is verified prior to connection.
2. **Private IP Guard:** Private (RFC 1918), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and reserved ranges are blocked immediately with zero geolocation calls.


# CyberScape (Phishing Rode) — Enterprise Cybersecurity & Threat Defense

CyberScape is an advanced threat-intelligence, phishing mitigation, and forensic analysis web platform built with Python (Flask) and modern responsive React-enhanced interfaces. The system shields users from malicious links, deceptive QR codes (quishing), and fraudulent email campaigns by analyzing destinations against live threat intelligence feeds, machine learning models, and cryptographic forensic verification before engagement.

---

## Key Modules & Features

### 1. Real-Time URL Scanner
- **Live Threat Intelligence:** Queries active threat feeds including abuse.ch URLhaus, VirusTotal API (v3), and Google Safe Browsing API (v4).
- **HTTP Redirect Sandbox Tracer:** Safely traces multi-hop redirect chains, exposing URL shortening cloaks and intermediate proxy hops without executing client-side scripts.
- **AI Domain Classification:** Random forest classifier evaluating Shannon entropy, IP heuristics, top-level domains, and lexical markers.
- **Geo-IP & Infrastructure Telemetry:** Resolves target IP and geographic server location with ASN and country flag telemetry.
- **React.js Frontend:** Asynchronous execution with `AbortController` timeout protection (15s), multi-step progress indicators, and user-friendly error banners.

### 2. In-Browser QR Code Scanner (Anti-Quishing)
- **Dual-Mode Decoding:** Live webcam scanner powered by `jsQR` with fallback to server-side OpenCV and pyzbar engines for uploaded image files.
- **Automated Verification Pipeline:** Automatically forwards extracted destination payloads to the threat analysis pipeline (`/qr-result`) without requiring secondary user actions.

### 3. AI Email & Header Threat Analyzer
- **Cryptographic Header Verification:** Evaluates raw RFC 822 email headers for SPF, DKIM, and DMARC alignment and authentication verdicts.
- **Sender Spoofing Detection:** Flags mismatches between `From`, `Return-Path`, and `Reply-To` headers, and identifies display name impersonation of high-profile brands.
- **NLP Phishing Intent Scoring:** Evaluates urgency, coercion, account suspension threats, and financial lures using heuristic pattern weighting.
- **Hyperlink Defanging & Originating IP Tracing:** Extracts embedded links, presents defanged previews, and resolves the earliest originating sender IP.

### 4. Admin Security Dashboard & Audit Logs
- **Dynamic Database Persistence:** Automatically logs all scan events (URL, QR, Email) into SQLite (`scan_logs`).
- **REST Telemetry APIs:**
  - `GET /api/dashboard/stats`: Returns live totals, low-risk, elevated-risk, and blocked counts.
  - `GET /api/dashboard/logs`: Server-side pagination, text search (`q`), and filtering by status/source.
- **Forensic PDF Export:** Instant PDF threat intelligence audit reports generated on-demand with ReportLab.

---

## API Endpoints Reference

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/check-url` | Analyzes a URL against ML, threat feeds, and redirect tracer | Yes (or preview) |
| `POST` | `/qr-result` | Analyzes a decoded QR destination link | Yes (or preview) |
| `POST` | `/decode-qr` | Server-side QR decoding for image files or base64 | Yes |
| `POST` | `/analyze-email` | Parses headers and analyzes text for phishing intent | Yes (or preview) |
| `GET` | `/api/dashboard/stats` | Returns aggregate counts and risk ratios | Yes |
| `GET` | `/api/dashboard/logs` | Returns paginated, searchable ingress scan records | Yes |
| `GET/POST`| `/generate-report` | Streams a forensic PDF report for a scanned URL | Yes |
| `GET/POST`| `/generate-email-report` | Streams a forensic PDF report for an analyzed email | Yes |

---

## Getting Started

### 1. Prerequisites
- Python 3.10+ (tested through Python 3.14)
- Virtual environment (`venv`)

### 2. Setup Virtual Environment & Dependencies
```bash
python -m venv .venv

# Windows
.\.venv\Scripts\activate
pip install -r requirements.txt

# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy `.env.example` to `.env` and set your optional API keys:
```bash
cp .env.example .env
```

Key variables in `.env`:
```env
CYBERSCAPE_SECRET_KEY=your-secure-random-key
PORT=5000
HOST=127.0.0.1
DEBUG=True

# Optional live feed keys (system falls back to public feeds and heuristics if omitted)
VIRUSTOTAL_API_KEY=
GOOGLE_SAFEBROWSING_API_KEY=
URLHAUS_API_KEY=
```

### 4. Running the Application
```bash
python app.py
```
Access the application at [http://127.0.0.1:5000](http://127.0.0.1:5000).

### 5. Running the Automated Test Suite
```bash
pytest
```
Executes all 36 unit, integration, and security access control tests.

---

## Default Development Credentials

- **Admin Email:** `admin@cyberscape.test`
- **Username:** `Admin`
- **Phone:** `+1234567890`
- **Password:** `admin123`

---

## License

Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R. All rights reserved.

Proprietary academic evaluation and personal learning license; redistribution, commercial hosting, unauthorized copying, or illegal security testing without written consent from all copyright holders is strictly prohibited. See [LICENSE](LICENSE) for full legal terms.

### Team
1. Jerald M Jolly
2. Bineesh Biju
3. Aston Mathew Felix
4. Adhul K R


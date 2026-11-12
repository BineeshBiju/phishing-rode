# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, Response, flash
from urllib.parse import urlparse
from functools import wraps
from io import BytesIO
import re
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import os
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from flask_cors import CORS
from backend.services.history_service import (
    format_history_record_for_inspect,
    detect_qr_payload_type,
    format_url_findings_and_checks,
    format_email_findings_and_checks
)
from backend.services.qr_analyzer import scan_qr_payload
from backend.services.rate_limiter import rate_limit

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("CYBERSCAPE_SECRET_KEY", "change-this-development-secret")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
DATABASE = Path(__file__).with_name("cyberscape.db")


@app.after_request
def add_cache_headers(response):
    if response.mimetype == "text/html" or request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.context_processor
def inject_current_year():
    return {"current_year": datetime.now().year}


def normalize_phone(value):
    return re.sub(r"\D", "", value or "")


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                phone TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                target_url TEXT NOT NULL,
                source TEXT NOT NULL,
                score INTEGER NOT NULL,
                status TEXT NOT NULL,
                level TEXT NOT NULL,
                time TEXT NOT NULL,
                domain TEXT,
                registrar TEXT,
                details_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cols = [col[1] for col in connection.execute("PRAGMA table_info(scan_logs)").fetchall()]
        if "user_email" not in cols:
            connection.execute("ALTER TABLE scan_logs ADD COLUMN user_email TEXT")
        if "details_json" not in cols:
            connection.execute("ALTER TABLE scan_logs ADD COLUMN details_json TEXT")
        if "domain" not in cols:
            connection.execute("ALTER TABLE scan_logs ADD COLUMN domain TEXT")
        if "registrar" not in cols:
            connection.execute("ALTER TABLE scan_logs ADD COLUMN registrar TEXT")
        admin_exists = connection.execute(
            "SELECT 1 FROM users WHERE email = ?", ("admin@cyberscape.test",)
        ).fetchone()
        if not admin_exists:
            connection.execute(
                "INSERT INTO users (name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    "Admin",
                    "admin@cyberscape.test",
                    "+1234567890",
                    generate_password_hash("admin123"),
                    datetime.now().isoformat(timespec="seconds")
                )
            )

def find_user_by_login(login_value):
    value = (login_value or "").strip().lower()
    if not value:
        return None

    numeric = normalize_phone(value)
    with get_db() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE lower(email) = ? OR lower(name) = ? OR phone = ?",
            (value, value, numeric or value)
        ).fetchone()


init_db()

GEO_LOOKUP = {
    "example.com": ("Los Angeles", "United States", 34.0522, -118.2437, "US", "93.184.216.34"),
    "update-account-verification.xyz": ("Reykjavik", "Iceland", 64.1466, -21.9426, "IS", "185.199.110.153"),
    "192.168.1.105": ("Frankfurt", "Germany", 50.1109, 8.6821, "DE", "192.168.1.105"),
    "github.com": ("San Francisco", "United States", 37.7749, -122.4194, "US", "140.82.121.4"),
    "bit.ly": ("New York", "United States", 40.7128, -74.0060, "US", "67.199.248.11"),
    "wikipedia.org": ("Ashburn", "United States", 39.0438, -77.4874, "US", "208.80.154.224"),
    "wellsfargo-security-check.top": ("Moscow", "Russia", 55.7558, 37.6173, "RU", "194.58.112.174"),
    "qr-event-checkin.live": ("Amsterdam", "Netherlands", 52.3676, 4.9041, "NL", "185.220.101.99"),
    "aws.amazon.com": ("Seattle", "United States", 47.6062, -122.3321, "US", "52.94.236.248"),
    "dhl-express-tracking-delivery.buzz": ("Bucharest", "Romania", 44.4268, 26.1025, "RO", "185.130.104.22"),
    "stackoverflow.com": ("Chicago", "United States", 41.8781, -87.6298, "US", "151.101.1.69"),
    "apple-id-cloud-verify.monster": ("Vilnius", "Lithuania", 54.6872, 25.2797, "LT", "185.220.102.8"),
    "qr-wifi-guest-portal.net": ("Austin", "United States", 30.2672, -97.7431, "US", "172.67.140.21"),
    "python.org": ("Paris", "France", 48.8566, 2.3522, "FR", "151.101.128.223"),
    "185.220.101.4": ("Berlin", "Germany", 52.5200, 13.4050, "DE", "185.220.101.4"),
    "t.co": ("San Francisco", "United States", 37.7749, -122.4194, "US", "104.244.42.193"),
    "cloudflare.com": ("San Jose", "United States", 37.3382, -121.8863, "US", "104.16.132.229"),
    "chase-bank-verify-portal.work": ("Sofia", "Bulgaria", 42.6977, 23.3219, "BG", "194.67.91.45"),
    "menu-restaurant-scan.xyz": ("Toronto", "Canada", 43.6532, -79.3832, "CA", "198.51.100.84"),
    "developer.mozilla.org": ("Mountain View", "United States", 37.3861, -122.0839, "US", "13.224.14.8"),
    "qr-payment-invoice-gateway.biz": ("Hong Kong", "Hong Kong", 22.3193, 114.1694, "HK", "103.251.167.90"),
    "netflix.com": ("Los Gatos", "United States", 37.2266, -121.9747, "US", "44.242.150.12"),
    "netflix-billing-update-2024.icu": ("Saint Petersburg", "Russia", 59.9343, 30.3351, "RU", "195.201.201.32"),
    "tinyurl.com": ("Dallas", "United States", 32.7767, -96.7970, "US", "104.20.10.11"),
    "linkedin.com": ("Sunnyvale", "United States", 37.3688, -122.0363, "US", "108.174.10.10"),
    "binance-kyc-aml-compliance.date": ("Singapore", "Singapore", 1.3521, 103.8198, "SG", "178.128.220.15"),
    "qr-event-pass.me": ("London", "United Kingdom", 51.5074, -0.1278, "GB", "185.199.108.153"),
    "docker.com": ("San Francisco", "United States", 37.7749, -122.4194, "US", "104.244.42.1"),
    "usps-address-confirm-redelivery.buzz": ("Kyiv", "Ukraine", 50.4501, 30.5234, "UA", "91.240.118.66"),
    "nist.gov": ("Gaithersburg", "United States", 39.1434, -77.2014, "US", "129.6.13.47"),
    "103.251.167.22": ("Seoul", "South Korea", 37.5665, 126.9780, "KR", "103.251.167.22"),
    "qr-loyalty-reward.club": ("São Paulo", "Brazil", -23.5505, -46.6333, "BR", "177.185.204.10"),
    "gitlab.com": ("Dublin", "Ireland", 53.3498, -6.2603, "IE", "172.65.251.78"),
    "steamcommunity-trade-gift.trade": ("Warsaw", "Poland", 52.2297, 21.0122, "PL", "194.26.29.112"),
    "parking-meter-quickpay.mobi": ("Sydney", "Australia", -33.8688, 151.2093, "AU", "13.239.88.42"),
    "nytimes.com": ("New York", "United States", 40.7128, -74.0060, "US", "151.101.65.164"),
    "wallet-connect-ledger-sync.ga": ("Lagos", "Nigeria", 6.5244, 3.3792, "NG", "197.210.226.4"),
    "zoom.us": ("San Jose", "United States", 37.3382, -121.8863, "US", "170.114.52.2"),
    "irs-tax-refund-direct-deposit.mom": ("Almaty", "Kazakhstan", 43.2220, 76.8512, "KZ", "195.189.97.10"),
    "cutt.ly": ("Warsaw", "Poland", 52.2297, 21.0122, "PL", "185.143.223.1"),
    "slack.com": ("San Francisco", "United States", 37.7749, -122.4194, "US", "151.101.193.140"),
    "suspicious-bank-login.com": ("Prague", "Czechia", 50.0755, 14.4378, "CZ", "185.220.103.4"),
    "qr-exhibit-guide.museum": ("Florence", "Italy", 43.7696, 11.2558, "IT", "193.205.156.2"),
    "bbc.com": ("London", "United Kingdom", 51.5074, -0.1278, "GB", "151.101.0.81"),
    "discord-nitro-free-3months.science": ("Riga", "Latvia", 56.9496, 24.1052, "LV", "185.220.101.5"),
    "salesforce.com": ("San Francisco", "United States", 37.7749, -122.4194, "US", "136.146.210.10"),
    "amazon-prime-payment-declined.rest": ("Istanbul", "Turkey", 41.0082, 28.9784, "TR", "185.255.45.18"),
    "transit-pass-scan.city": ("Tokyo", "Japan", 35.6762, 139.6503, "JP", "133.242.18.2"),
    "dropbox.com": ("San Francisco", "United States", 37.7749, -122.4194, "US", "162.125.6.1"),
    "free-crypto-giveaway-airdrop.live": ("Panama City", "Panama", 8.9824, -79.5199, "PA", "190.14.36.12")
}

# Real-Time User Activity Logging (Clean history by default)
scan_history = []


def log_scan_record(record, user_email=None):
    """Dynamically log an authentic user scan result (URL, QR, Email) into the SQLite database."""
    try:
        email = user_email or session.get("user") or "admin@cyberscape.test"
        orig_source = record.get("source") or record.get("scan_type") or "URL"
        db_source = str(orig_source).upper()
        if db_source in ("INSPECTOR", "AUDIT"):
            db_source = "URL"
        score = int(record.get("score") or 0)
        status = (record.get("status") or record.get("verdict") or "SAFE").upper()
        level = record.get("level") or ("Low Risk" if status == "SAFE" else ("Critical Threat" if status == "MALICIOUS" else "Elevated Risk"))
        time_str = record.get("time") or record.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if db_source == "EMAIL":
            sender = (
                record.get("sender_check", {}).get("from_addr")
                or record.get("from_addr")
                or record.get("host")
                or "Email Sender"
            )
            subject = (
                record.get("header_analysis", {}).get("subject")
                or record.get("subject")
                or record.get("content_findings", {}).get("subject")
                or ""
            )
            if subject and subject != "No Subject":
                url = f"{sender} — {subject}"
            else:
                url = sender
            domain = record.get("sender_check", {}).get("from_domain") or (sender.split("@")[-1] if "@" in sender else "email.destination")
            registrar = (
                record.get("origin_ip", {}).get("isp")
                or record.get("origin_ip", {}).get("country")
                or "Email Transmission Node"
            )
            if "passed_checks" not in record or not record.get("passed_checks"):
                findings, passed_checks, technical = format_email_findings_and_checks(record)
                record["findings"] = findings
                record["passed_checks"] = passed_checks
                record["technical_details"] = technical
        else:
            url = record.get("url") or record.get("target_url") or "Web Probe Destination"
            parsed = urlparse(url)
            domain = record.get("host") or record.get("domain") or parsed.hostname or "Autonomous"
            registrar = record.get("registrar") or record.get("geo_ip", {}).get("org") or record.get("geo_ip", {}).get("isp") or "Enterprise Host Network"
            if "passed_checks" not in record or not record.get("passed_checks"):
                findings, passed_checks, technical = format_url_findings_and_checks(record)
                record["findings"] = findings
                record["passed_checks"] = passed_checks
                record["technical_details"] = technical
            if db_source == "QR":
                record["payload_type"] = detect_qr_payload_type(url)

        # Standardize top-level fields in record before json serialization
        record["target"] = url
        record["target_url"] = url
        record["scan_type"] = db_source
        record["source"] = orig_source
        record["score"] = score
        record["status"] = status
        record["verdict"] = status
        record["level"] = level
        record["timestamp"] = time_str

        with get_db() as connection:
            connection.execute(
                """
                INSERT INTO scan_logs (user_email, target_url, source, score, status, level, time, domain, registrar, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (email, url, db_source, score, status, level, time_str, domain, registrar, json.dumps(record))
            )
    except Exception as e:
        app.logger.warning(f"Could not persist scan to database: {e}")



def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user" not in session:
            if app.config.get("TESTING") and not request.headers.get("X-Test-Guest"):
                session["user"] = "admin@cyberscape.test"
                session["name"] = "Admin"
                return view_func(*args, **kwargs)
            if request.is_json or request.path in ["/threat-map-data", "/check-url", "/qr-result", "/decode-qr", "/analyze-email", "/inspect"]:
                return jsonify({"error": "Authentication required. Please sign in or register to access this feature."}), 401
            return redirect(url_for("login", error="Please log in to access this feature."))
        return view_func(*args, **kwargs)
    return wrapped_view


import ml_engine
import threat_intel
import geo_resolver
import redirect_tracer
import qr_decoder
import report_generator
import email_analyzer
import audit_service
from backend.services.orchestrator import scan_url, clear_scan_cache


def verdict_from_score(score: int) -> dict:
    """
    Centralized single source of truth for deriving security verdict from risk score.
    Score ranges:
      0..29  -> Low risk / Safe
      30..69 -> Elevated risk / Suspicious
      70..100 -> High risk / Malicious
    """
    score = max(0, min(100, int(score)))
    if score >= 70:
        return {
            "status": "MALICIOUS",
            "level": "High Risk",
            "verdict": "High risk, do not open",
            "color": "danger"
        }
    if score >= 30:
        return {
            "status": "SUSPICIOUS",
            "level": "Elevated Risk",
            "verdict": "Elevated risk, proceed with caution",
            "color": "warning"
        }
    return {
        "status": "SAFE",
        "level": "Low Risk",
        "verdict": "Low risk, verified safe",
        "color": "safe"
    }


def query_urlhaus(url):
    return threat_intel.query_urlhaus(url)


def analyze_url(url, trace_redirects_flag=True):
    """
    Perform deep multi-layered cybersecurity analysis across:
    1. AI ML Phishing Domain Detection
    2. Real-Time Threat Intelligence (URLhaus, VirusTotal, Google Safe Browsing, OpenPhish)
    3. DNS, TLS, RDAP Domain Age & Geo-IP Telemetry
    4. SSRF-Safe HTTP Sandbox Redirect Tracer
    """
    return scan_url(url)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/license")
def license_page():
    return render_template("license.html")

@app.route("/scanner")
@login_required
def scanner():
    return render_template("scanner.html")

@app.route("/qr-scanner")
@login_required
def qr_scanner():
    return render_template("qr_scanner.html")

@app.route("/email-analyzer")
@login_required
def email_analyzer_page():
    return render_template("email_analyzer.html")

@app.route("/analysis")
@login_required
def analysis():
    return render_template("analysis.html")

@app.route("/blocked")
@login_required
def blocked():
    return render_template("blocked.html")

@app.route("/admin")
@app.route("/dashboard", endpoint="dashboard")
@login_required
def admin():
    current_user = session.get("user")
    normalized_history = []
    with get_db() as conn:
        if current_user:
            rows = conn.execute(
                "SELECT * FROM scan_logs WHERE user_email = ? ORDER BY id DESC",
                (current_user,)
            ).fetchall()
        else:
            rows = []

        for r in rows:
            details = {}
            if r["details_json"]:
                try:
                    details = json.loads(r["details_json"])
                except Exception:
                    details = {}
            url = r["target_url"] or ""
            parsed = urlparse(url)
            proto = "HTTPS" if url.startswith("https://") else ("HTTP" if url.startswith("http://") else ("QR" if r["source"] == "QR" else "EMAIL"))
            host = r["domain"] or parsed.hostname or "Autonomous"
            registrar = r["registrar"] or "Enterprise Host Network"
            geo_ip = details.get("geo_ip") or {
                "city": "Autonomous",
                "country": "Global Network",
                "latitude": 37.751,
                "longitude": -122.42,
                "ip": "Unresolved"
            }

            sender = ""
            subject = ""
            auth_summary = ""
            if r["source"] == "EMAIL":
                sender = details.get("sender_check", {}).get("from_addr") or details.get("header_analysis", {}).get("from_addr") or r["domain"] or "Email Sender"
                subject = details.get("header_analysis", {}).get("subject") or details.get("content_findings", {}).get("subject") or ""
                spf_st = details.get("auth_results", {}).get("spf", {})
                spf_val = spf_st.get("status") if isinstance(spf_st, dict) else str(spf_st or "PASS")
                auth_summary = f"SPF: {spf_val}"

            normalized_history.append({
                "id": r["id"],
                "url": url,
                "protocol": proto,
                "host": host,
                "registrar": registrar,
                "source": r["source"],
                "score": r["score"],
                "status": r["status"],
                "level": r["level"],
                "time": r["time"],
                "geo_ip": geo_ip,
                "sender": sender,
                "subject": subject,
                "auth_summary": auth_summary,
                "reasons": details.get("reasons") or []
            })

    url_count = sum(1 for x in normalized_history if x.get("source") in ("URL", "INSPECTOR", "AUDIT"))
    qr_count = sum(1 for x in normalized_history if x.get("source") == "QR")
    email_count = sum(1 for x in normalized_history if x.get("source") == "EMAIL")
    total_count = url_count + qr_count + email_count

    stats = {
        "total": total_count,
        "safe": sum(1 for x in normalized_history if x["status"] == "SAFE"),
        "suspicious": sum(1 for x in normalized_history if x["status"] == "SUSPICIOUS"),
        "blocked": sum(1 for x in normalized_history if x["status"] == "MALICIOUS"),
        "qr": qr_count,
        "url": url_count,
        "email": email_count
    }

    threat_map_records = []
    country_counts = {}

    for row in normalized_history:
        geo = row.get("geo_ip") or {}
        lat = geo.get("latitude")
        lon = geo.get("longitude")
        if lat is not None and lon is not None:
            country = geo.get("country", "Unknown")
            flag = geo.get("flag", "")
            threat_map_records.append({
                "url": row["url"],
                "host": row["host"],
                "registrar": row["registrar"],
                "protocol": row["protocol"],
                "source": row["source"],
                "score": row["score"],
                "status": row["status"],
                "level": row["level"],
                "time": row["time"],
                "lat": lat,
                "lon": lon,
                "city": geo.get("city", "Unknown City"),
                "country": country,
                "flag": flag,
                "ip": geo.get("ip", "Unknown IP")
            })
            if country not in country_counts:
                country_counts[country] = {"country": country, "flag": flag, "total": 0, "malicious": 0, "lat": lat, "lon": lon}
            country_counts[country]["total"] += 1
            if row["status"] == "MALICIOUS":
                country_counts[country]["malicious"] += 1

    top_hotspots = sorted(country_counts.values(), key=lambda c: (c["malicious"], c["total"]), reverse=True)[:6]

    return render_template(
        "admin.html",
        stats=stats,
        history=normalized_history,
        total_count=stats["total"],
        url_count=stats["url"],
        qr_count=stats["qr"],
        email_count=stats["email"],
        threat_map_json=json.dumps(threat_map_records),
        top_hotspots=top_hotspots,
        user=session.get("user"),
        active_nav="dashboard"
    )

@app.route("/threat-map-data")
@login_required
def threat_map_data():
    current_user = session.get("user")
    records = []
    with get_db() as conn:
        if current_user:
            rows = conn.execute("SELECT * FROM scan_logs WHERE user_email = ? ORDER BY id DESC", (current_user,)).fetchall()
        else:
            rows = []
        for r in rows:
            details = {}
            if r["details_json"]:
                try:
                    details = json.loads(r["details_json"])
                except Exception:
                    pass
            geo = details.get("geo_ip") or {}
            lat = geo.get("latitude")
            lon = geo.get("longitude")
            if lat is not None and lon is not None:
                records.append({
                    "url": r["target_url"],
                    "host": r["domain"],
                    "status": r["status"],
                    "score": r["score"],
                    "lat": lat,
                    "lon": lon,
                    "city": geo.get("city"),
                    "country": geo.get("country"),
                    "flag": geo.get("flag"),
                    "ip": geo.get("ip")
                })
    return jsonify({"success": True, "count": len(records), "data": records})

@app.route("/api/dashboard/stats", methods=["GET"])
@login_required
def api_dashboard_stats():
    """Live dashboard aggregate telemetry metrics from SQLite database."""
    try:
        current_user = session.get("user")
        with get_db() as conn:
            if current_user:
                safe = conn.execute("SELECT COUNT(*) FROM scan_logs WHERE user_email = ? AND status = 'SAFE'", (current_user,)).fetchone()[0]
                suspicious = conn.execute("SELECT COUNT(*) FROM scan_logs WHERE user_email = ? AND status = 'SUSPICIOUS'", (current_user,)).fetchone()[0]
                blocked = conn.execute("SELECT COUNT(*) FROM scan_logs WHERE user_email = ? AND status = 'MALICIOUS'", (current_user,)).fetchone()[0]
                url_count = conn.execute("SELECT COUNT(*) FROM scan_logs WHERE user_email = ? AND (source = 'URL' OR source = 'INSPECTOR' OR source = 'AUDIT')", (current_user,)).fetchone()[0]
                qr_count = conn.execute("SELECT COUNT(*) FROM scan_logs WHERE user_email = ? AND source = 'QR'", (current_user,)).fetchone()[0]
                email_count = conn.execute("SELECT COUNT(*) FROM scan_logs WHERE user_email = ? AND source = 'EMAIL'", (current_user,)).fetchone()[0]
                total = url_count + qr_count + email_count
            else:
                total = safe = suspicious = blocked = url_count = qr_count = email_count = 0

        return jsonify({
            "success": True,
            "total": total,
            "safe": safe,
            "suspicious": suspicious,
            "blocked": blocked,
            "url": url_count,
            "qr": qr_count,
            "email": email_count,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/dashboard/logs", methods=["GET"])
@login_required
def api_dashboard_logs():
    """Dynamic paginated ingress logs with search filtering from SQLite database."""
    try:
        current_user = session.get("user")
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(5, int(request.args.get("per_page", 20))))
        offset = (page - 1) * per_page
        q = (request.args.get("q") or "").strip().lower()
        status_filter = (request.args.get("status") or "").strip().upper()
        source_filter = (request.args.get("source") or "").strip().upper()

        where_clauses = ["user_email = ?"] if current_user else ["1=0"]
        params = [current_user] if current_user else []

        if q:
            where_clauses.append("(lower(target_url) LIKE ? OR lower(domain) LIKE ? OR lower(registrar) LIKE ?)")
            param_q = f"%{q}%"
            params.extend([param_q, param_q, param_q])

        if status_filter in ["SAFE", "SUSPICIOUS", "MALICIOUS"]:
            where_clauses.append("status = ?")
            params.append(status_filter)

        if source_filter == "URL":
            where_clauses.append("(source = 'URL' OR source = 'INSPECTOR' OR source = 'AUDIT')")
        elif source_filter in ["QR", "EMAIL"]:
            where_clauses.append("source = ?")
            params.append(source_filter)

        where_str = " AND ".join(where_clauses)

        with get_db() as conn:
            total_matches = conn.execute(f"SELECT COUNT(*) FROM scan_logs WHERE {where_str}", params).fetchone()[0]
            query = f"SELECT * FROM scan_logs WHERE {where_str} ORDER BY id DESC LIMIT ? OFFSET ?"
            query_params = list(params) + [per_page, offset]
            rows = conn.execute(query, query_params).fetchall()

            logs = []
            for r in rows:
                details = {}
                if r["details_json"]:
                    try:
                        details = json.loads(r["details_json"])
                    except Exception:
                        details = {}
                geo = details.get("geo_ip") or {}
                source_val = (r["source"] or "URL").upper()
                proto = "HTTPS" if (r["target_url"] or "").startswith("https://") else ("HTTP" if (r["target_url"] or "").startswith("http://") else ("QR" if source_val == "QR" else "EMAIL"))

                sender = ""
                subject = ""
                auth_summary = ""
                if source_val == "EMAIL":
                    sender = details.get("sender_check", {}).get("from_addr") or details.get("header_analysis", {}).get("from_addr") or r["domain"] or "Email Sender"
                    subject = details.get("header_analysis", {}).get("subject") or details.get("content_findings", {}).get("subject") or ""
                    spf_st = details.get("auth_results", {}).get("spf", {})
                    spf_val = spf_st.get("status") if isinstance(spf_st, dict) else str(spf_st or "PASS")
                    auth_summary = f"SPF: {spf_val}"

                logs.append({
                    "id": r["id"],
                    "url": r["target_url"],
                    "source": source_val,
                    "protocol": proto,
                    "score": r["score"],
                    "status": r["status"],
                    "level": r["level"],
                    "time": r["time"],
                    "domain": r["domain"],
                    "host": r["domain"],
                    "registrar": r["registrar"],
                    "geo_ip": geo,
                    "sender": sender,
                    "subject": subject,
                    "auth_summary": auth_summary
                })

        return jsonify({
            "success": True,
            "logs": logs,
            "total": total_matches,
            "page": page,
            "per_page": per_page,
            "pages": (total_matches + per_page - 1) // per_page if total_matches else 1
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("admin"))

    error = request.args.get("error")
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        remember = request.form.get("remember") == "on"

        if not username or not password:
            error = "Please enter both your username, email, or phone number and password."
        else:
            user = find_user_by_login(username)
            if user is None or not check_password_hash(user["password_hash"], password):
                error = "Invalid login. Try admin, admin@cyberscape.test, or +1234567890 with password admin123."
            else:
                session.clear()
                session["user"] = user["email"]
                session["name"] = user["name"]
                session.permanent = remember
                return redirect(url_for("admin"))

    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect(url_for("admin"))

    error = None
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        phone = (request.form.get("phone") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not all([name, email, phone, password, confirm_password]):
            error = "Please complete all registration fields."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif len(password) < 6:
            error = "Password must be at least 6 characters long."
        elif find_user_by_login(email) or find_user_by_login(phone) or find_user_by_login(name):
            error = "An account with that email, phone number, or name already exists."
        else:
            try:
                with get_db() as connection:
                    connection.execute(
                        "INSERT INTO users (name, email, phone, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            name,
                            email,
                            normalize_phone(phone),
                            generate_password_hash(password),
                            datetime.now().isoformat(timespec="seconds")
                        )
                    )
                session.clear()
                session["user"] = email
                session["name"] = name
                session.permanent = True
                return redirect(url_for("admin"))
            except sqlite3.IntegrityError:
                error = "An account with that email or phone number already exists."

    return render_template("register.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.post("/inspect")
@rate_limit(limit=60, window_seconds=60)
def inspect():
    if not session.get("user") and not app.config.get("TESTING"):
        return jsonify({"error": "Authentication required. Please sign in or register to run threat scans."}), 401

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL to inspect."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL exceeds maximum supported length (2,048 characters)."}), 400

    result = analyze_url(url)
    result["source"] = data.get("source", "INSPECTOR")
    result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_history.append(result)
    log_scan_record(result, session.get("user"))
    return jsonify(result)

@app.post("/check-url")
@rate_limit(limit=60, window_seconds=60)
def check_url():
    if not session.get("user") and not app.config.get("TESTING"):
        return jsonify({"error": "Authentication required. Please sign in or register to run threat scans."}), 401

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL exceeds maximum supported length (2,048 characters)."}), 400

    result = analyze_url(url)
    result["source"] = "URL"
    result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_history.append(result)
    log_scan_record(result, session.get("user"))
    return jsonify(result)

@app.post("/qr-result")
@rate_limit(limit=60, window_seconds=60)
def qr_result():
    if not session.get("user") and not app.config.get("TESTING"):
        return jsonify({"error": "Authentication required. Please sign in or register to run threat scans."}), 401

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or data.get("payload") or "").strip()
    if not url:
        return jsonify({"error": "No QR payload was extracted from the QR image."}), 400
    if len(url) > 4096:
        return jsonify({"error": "QR payload exceeds maximum supported length (4,096 characters)."}), 400

    result = scan_qr_payload(url)
    result["source"] = "QR"
    result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_history.append(result)
    log_scan_record(result, session.get("user"))
    return jsonify(result)

@app.post("/decode-qr")
@login_required
@rate_limit(limit=60, window_seconds=60)
def decode_qr():
    # Support multipart file upload
    if "qr_file" in request.files or "image" in request.files:
        file = request.files.get("qr_file") or request.files.get("image")
        if not file or file.filename == "":
            return jsonify({"success": False, "error": "No file uploaded"}), 400
        image_bytes = file.read()
        if not image_bytes or len(image_bytes) == 0:
            return jsonify({"success": False, "error": "The uploaded image file is empty."}), 400
        if len(image_bytes) > 15 * 1024 * 1024:
            return jsonify({"success": False, "error": "Image file exceeds maximum allowed size of 15 MB."}), 400
        res = qr_decoder.decode_qr_image_bytes(image_bytes)
        return jsonify(res)

    # Support JSON base64
    data = request.get_json(silent=True) or {}
    b64_image = data.get("image_base64") or data.get("image")
    if b64_image:
        res = qr_decoder.decode_qr_base64(b64_image)
        return jsonify(res)

    return jsonify({"success": False, "error": "No image data or file provided."}), 400

@app.post("/api/audit")
@rate_limit(limit=60, window_seconds=60)
def api_audit():
    if not session.get("user") and not app.config.get("TESTING"):
        return jsonify({"error": "Authentication required. Please sign in or register to run security audits."}), 401

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or data.get("target_url") or "").strip()
    authorized = bool(data.get("authorized", False))

    if not authorized:
        return jsonify({"error": "Target authorization checkbox must be confirmed before auditing."}), 400

    if not url:
        return jsonify({"error": "Please provide a target URL to audit."}), 400

    try:
        audit_res = audit_service.run_security_audit(url, authorized=authorized)
        audit_record = {
            "url": audit_res["target_url"],
            "final_url": audit_res["final_url"],
            "score": audit_res["risk_score"],
            "status": audit_res["status"],
            "level": audit_res["threat_level"],
            "source": "AUDIT",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reasons": audit_res["reasons"]
        }
        scan_history.append(audit_record)
        log_scan_record(audit_record, session.get("user"))
        return jsonify(audit_res)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Security audit encountered an error: {str(e)}"}), 500

@app.route("/generate-report", methods=["GET", "POST"])
@login_required
def generate_report():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
    else:
        url = request.args.get("url", "").strip()
        data = {"url": url}

    target_url = data.get("url")
    if not target_url:
        return jsonify({"error": "No target URL provided for forensic report generation."}), 400

    # If full scan payload was passed, use it; otherwise check database or run analysis
    if "ml_analysis" in data and "threat_intel" in data and "geo_ip" in data:
        scan_payload = data
    else:
        with get_db() as conn:
            saved = conn.execute(
                "SELECT details_json FROM scan_logs WHERE target_url = ? ORDER BY id DESC LIMIT 1",
                (target_url,)
            ).fetchone()
            if saved and saved["details_json"]:
                try:
                    scan_payload = json.loads(saved["details_json"])
                except Exception:
                    scan_payload = None
            else:
                scan_payload = None

        if not scan_payload:
            scan_payload = analyze_url(target_url)
            scan_payload["source"] = data.get("source", "Forensic Audit")
            scan_payload["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # If it was an Email scan, generate email report; else generate URL/QR forensic report
    if scan_payload.get("source") == "EMAIL" or "header_analysis" in scan_payload or "email_body_analysis" in scan_payload:
        pdf_bytes = report_generator.generate_email_forensic_pdf(scan_payload)
        filename = f"CyberScape_Email_Forensic_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    else:
        pdf_bytes = report_generator.generate_forensic_pdf(scan_payload)
        safe_host = re.sub(r"[^a-zA-Z0-9_-]", "_", urlparse(target_url).hostname or "target")
        filename = f"CyberScape_Forensic_Report_{safe_host}.pdf"

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )

@app.post("/analyze-email")
@rate_limit(limit=60, window_seconds=60)
def analyze_email():
    if not session.get("user") and not app.config.get("TESTING"):
        return jsonify({"error": "Authentication required. Please sign in or register to run threat scans."}), 401

    try:
        # 1. Support .eml file upload via multipart/form-data
        if "eml_file" in request.files or "file" in request.files:
            file = request.files.get("eml_file") or request.files.get("file")
            if not file or file.filename == "":
                return jsonify({"error": "No .eml file was selected for upload."}), 400
            file_bytes = file.read()
            if not file_bytes:
                return jsonify({"error": "The uploaded .eml file is empty."}), 400
            if len(file_bytes) > 15 * 1024 * 1024:
                return jsonify({"error": "Email file exceeds maximum allowed size of 15 MB."}), 400
            result = email_analyzer.analyze_eml_file_or_bytes(file_bytes, filename=file.filename)
        else:
            # 2. Support JSON payloads
            data = request.get_json(silent=True) or {}
            raw_email = data.get("raw_email") or data.get("eml_content") or ""
            if raw_email and str(raw_email).strip():
                if len(str(raw_email).encode("utf-8")) > 15 * 1024 * 1024:
                    return jsonify({"error": "Raw email exceeds maximum allowed size of 15 MB."}), 400
                result = email_analyzer.analyze_eml_file_or_bytes(raw_email)
            else:
                header_text = data.get("header") or data.get("header_text") or ""
                content_text = data.get("body") or data.get("content_text") or data.get("content") or ""

                if not str(header_text).strip() and not str(content_text).strip():
                    return jsonify({"error": "Please provide an email header, email message content, or upload an .eml file."}), 400

                result = email_analyzer.full_email_investigation(header_text, content_text)
        result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Log to scan history and persist to database
        email_sender = (
            result.get("sender_check", {}).get("from_addr")
            or result.get("header_analysis", {}).get("from_addr")
            or result.get("sender_check", {}).get("from_domain")
            or "Email Message"
        )
        email_subject = result.get("header_analysis", {}).get("subject") or result.get("content_findings", {}).get("subject") or ""
        email_title = f"{email_sender} — {email_subject}" if email_subject and email_subject != "No Subject" else email_sender

        findings, passed_checks, technical = format_email_findings_and_checks(result)
        email_entry = {
            "url": email_title,
            "target_url": email_title,
            "target": email_title,
            "score": result.get("score", 0),
            "status": result.get("verdict", "UNKNOWN"),
            "verdict": result.get("verdict", "UNKNOWN"),
            "level": result.get("level", "Standard"),
            "reasons": result.get("risk_factors", []),
            "source": "EMAIL",
            "time": result["time"],
            "host": result.get("sender_check", {}).get("from_domain") or "email.destination",
            "registrar": result.get("origin_ip", {}).get("isp") or "Email Transmission Node",
            "findings": findings,
            "passed_checks": passed_checks,
            "technical_details": technical,
            "header_analysis": result.get("header_analysis", {}),
            "email_body_analysis": result.get("content_findings", {}),
            "sender_check": result.get("sender_check", {}),
            "auth_results": result.get("auth_results", {}),
            "origin_ip": result.get("origin_ip", {}),
            "links": result.get("links", []),
            "recommendations": result.get("recommendations", [])
        }
        scan_history.append(email_entry)
        log_scan_record(email_entry, session.get("user"))

        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Email analysis error: {e}", exc_info=True)
        return jsonify({"error": f"Failed to analyze email: {str(e)}"}), 500

@app.route("/api/history/<int:record_id>", methods=["GET"])
@login_required
def api_history_detail(record_id):
    """Retrieve full structured forensic details for inspection modal."""
    current_user = session.get("user")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scan_logs WHERE id = ?", (record_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "error": "Forensic audit record not found."}), 404

        # Security: ownership verification
        if row["user_email"] != current_user and current_user != "admin@cyberscape.test":
            return jsonify({"success": False, "error": "Unauthorized access to this forensic record."}), 403

        record = format_history_record_for_inspect(dict(row))
        return jsonify({"success": True, "record": record})

@app.route("/history/<int:record_id>/report.pdf", methods=["GET"])
@login_required
def history_record_pdf(record_id):
    """Download enterprise ReportLab PDF forensic report for a historical scan record."""
    current_user = session.get("user")
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scan_logs WHERE id = ?", (record_id,)).fetchone()
        if not row:
            return jsonify({"error": "Forensic audit record not found."}), 404

        # Security: ownership verification
        if row["user_email"] != current_user and current_user != "admin@cyberscape.test":
            return jsonify({"error": "Unauthorized access to this forensic report."}), 403

        record = format_history_record_for_inspect(dict(row))
        pdf_bytes = report_generator.generate_history_record_pdf(record)

        scan_type = (record.get("scan_type") or "AUDIT").upper()
        date_str = datetime.now().strftime("%Y%m%d")
        filename = f"CyberScape_Report_{scan_type}_{record_id}_{date_str}.pdf"

        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf"
            }
        )

@app.route("/history/export-all.pdf", methods=["GET"])
@login_required
def history_export_all_pdf():
    """Download consolidated audit trail PDF covering all scans for authenticated user."""
    current_user = session.get("user")
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM scan_logs WHERE user_email = ? ORDER BY id DESC", (current_user,)).fetchall()
        records = [format_history_record_for_inspect(dict(r)) for r in rows]
        pdf_bytes = report_generator.generate_all_history_pdf(records, current_user)
        filename = f"CyberScape_All_History_{datetime.now().strftime('%Y%m%d')}.pdf"

        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf"
            }
        )

@app.route("/generate-email-report", methods=["GET", "POST"])
@login_required
def generate_email_report():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
    else:
        header_text = request.args.get("header_text", "")
        content_text = request.args.get("content_text", "")
        data = email_analyzer.full_email_investigation(header_text, content_text)
        data["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not data or "verdict" not in data:
        header_text = data.get("header_text", "")
        content_text = data.get("content_text", "")
        data = email_analyzer.full_email_investigation(header_text, content_text)
        data["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pdf_bytes = report_generator.generate_email_forensic_pdf(data)
    filename = f"CyberScape_Email_Forensic_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename
    )

if __name__ == "__main__":
    app.run(debug=True)

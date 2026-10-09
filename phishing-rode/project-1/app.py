from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from urllib.parse import urlparse
from functools import wraps
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import os
import requests
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.getenv("CYBERSCAPE_SECRET_KEY", "change-this-development-secret")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
DATABASE = Path(__file__).with_name("cyberscape.db")

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

scan_history = []


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login", error="Please log in to access this feature."))
        return view_func(*args, **kwargs)
    return wrapped_view


def query_urlhaus(url):
    response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=8)
    response.raise_for_status()
    data = response.json()
    if data.get("query_status") == "ok":
        return {"status": "MALICIOUS", "reason": "URLhaus lists this URL as a malware threat."}
    if data.get("query_status") == "no_results":
        return {"status": "NO_MATCH", "reason": "URLhaus returned no matching threat record."}
    return {"status": "UNAVAILABLE", "reason": "URLhaus returned an unusable response."}


def analyze_url(url):
    """Check a URL against the live URLhaus threat-intelligence service."""
    cleaned = (url or "").strip()
    if not cleaned:
        return {"url": cleaned, "score": 0, "status": "INVALID", "level": "No Result", "reasons": ["No URL provided for analysis."]}
    if not re.match(r"^https?://", cleaned, re.I):
        return {"url": cleaned, "score": 0, "status": "INVALID", "level": "No Result", "reasons": ["Only HTTP and HTTPS URLs can be checked."]}
    if not urlparse(cleaned).hostname:
        return {"url": cleaned, "score": 0, "status": "INVALID", "level": "No Result", "reasons": ["The URL does not contain a valid hostname."]}

    try:
        checks = [("URLhaus", query_urlhaus(cleaned))]
    except requests.RequestException:
        checks = [("URLhaus", {"status": "UNAVAILABLE", "reason": "URLhaus could not be reached."})]
    except (ValueError, KeyError):
        checks = [("URLhaus", {"status": "UNAVAILABLE", "reason": "URLhaus returned invalid data."})]

    matches = [result["reason"] for _, result in checks if result["status"] == "MALICIOUS"]
    available = [result for _, result in checks if result["status"] in {"MALICIOUS", "NO_MATCH"}]
    if matches:
        status, level, score = "MALICIOUS", "High Risk", 100
        reasons = matches
    elif available:
        status, level, score = "SAFE", "Low Risk", 0
        reasons = [result["reason"] for _, result in checks if result["status"] == "NO_MATCH"]
    else:
        status, level, score = "UNKNOWN", "Unable to Verify", 0
        reasons = [result["reason"] for _, result in checks]
    return {"url": cleaned, "score": score, "status": status, "level": level, "reasons": reasons}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scanner")
@login_required
def scanner():
    return render_template("scanner.html")

@app.route("/qr-scanner")
@login_required
def qr_scanner():
    return render_template("qr_scanner.html")

@app.route("/analysis")
@login_required
def analysis():
    return render_template("analysis.html")

@app.route("/blocked")
@login_required
def blocked():
    return render_template("blocked.html")

@app.route("/admin")
@login_required
def admin():
    stats = {
        "total": len(scan_history),
        "safe": sum(x["status"] == "SAFE" for x in scan_history),
        "suspicious": sum(x["status"] == "SUSPICIOUS" for x in scan_history),
        "blocked": sum(x["status"] == "MALICIOUS" for x in scan_history),
        "qr": sum(x.get("source") == "QR" for x in scan_history)
    }
    return render_template("admin.html", stats=stats, history=scan_history[-10:][::-1], user=session.get("user"))

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
    return redirect(url_for("login", error="You have been logged out."))

@app.post("/api/check-url")
def check_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    result = analyze_url(url)
    result["source"] = "URL"
    result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_history.append(result)
    return jsonify(result)

@app.post("/api/qr-result")
def qr_result():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL was extracted from the QR image."}), 400

    result = analyze_url(url)
    result["source"] = "QR"
    result["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_history.append(result)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)

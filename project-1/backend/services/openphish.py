# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
OpenPhish Community Feed Service
Periodically synchronizes and matches URLs against the live OpenPhish community threat feed.
"""

from urllib.parse import urlparse
from pathlib import Path
import os
import time
import requests

OPENPHISH_CACHE_FILE = Path(__file__).parent.parent / "data" / "openphish_feed.txt"
FEED_TTL_SECONDS = 14400  # 4 hours


def update_openphish_feed():
    try:
        OPENPHISH_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        resp = requests.get("https://openphish.com/feed.txt", timeout=6.0)
        if resp.status_code == 200 and resp.text:
            OPENPHISH_CACHE_FILE.write_text(resp.text, encoding="utf-8")
    except Exception:
        pass


def get_cached_feed_urls() -> set[str]:
    if not OPENPHISH_CACHE_FILE.exists():
        update_openphish_feed()

    if OPENPHISH_CACHE_FILE.exists():
        # Check file age
        mtime = OPENPHISH_CACHE_FILE.stat().st_mtime
        if time.time() - mtime > FEED_TTL_SECONDS:
            update_openphish_feed()
        try:
            lines = OPENPHISH_CACHE_FILE.read_text(encoding="utf-8").splitlines()
            return {line.strip().lower() for line in lines if line.strip()}
        except Exception:
            return set()
    return set()


def query_openphish(url: str, timeout: float = 4.0) -> dict:
    clean_url = url.strip().lower().rstrip("/")
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    # 1. Query PhishTank API if API key configured
    phishtank_key = os.getenv("PHISHTANK_API_KEY", "").strip()
    if phishtank_key:
        try:
            pt_resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json", "app_key": phishtank_key},
                headers={"User-Agent": "phishtank/cyberscape-2.0"},
                timeout=timeout
            )
            if pt_resp.status_code == 200:
                pt_data = pt_resp.json().get("results", {})
                if pt_data.get("in_database") and pt_data.get("valid"):
                    reason = "Target URL is confirmed active phishing in PhishTank database."
                    return {
                        "source": "OpenPhish / PhishTank",
                        "status": "MALICIOUS",
                        "verdict": "Active Phishing",
                        "available": True,
                        "reason": reason,
                        "signal": {
                            "id": "phishtank_match",
                            "source": "PhishTank Feed",
                            "severity": "critical",
                            "score_impact": 95,
                            "evidence": reason
                        }
                    }
        except Exception:
            pass

    # 2. Check OpenPhish Community Feed
    feed = get_cached_feed_urls()
    is_match = clean_url in feed or any(hostname and hostname in f_url for f_url in feed)

    if is_match:
        reason = "Target URL is listed in active OpenPhish threat intelligence feed."
        return {
            "source": "OpenPhish / PhishTank",
            "status": "MALICIOUS",
            "verdict": "Active Phishing",
            "available": True,
            "reason": reason,
            "signal": {
                "id": "openphish_match",
                "source": "OpenPhish Feed",
                "severity": "critical",
                "score_impact": 90,
                "evidence": reason
            }
        }

    is_avail = bool(feed or phishtank_key)
    return {
        "source": "OpenPhish / PhishTank",
        "status": "SAFE" if is_avail else "UNAVAILABLE",
        "verdict": "Clean" if is_avail else "Unavailable",
        "available": is_avail,
        "reason": "Not listed in OpenPhish or PhishTank databases." if is_avail else "OpenPhish / PhishTank feed unavailable.",
        "signal": {
            "id": "openphish_clean" if is_avail else "openphish_unavail",
            "source": "OpenPhish Feed",
            "severity": "safe" if is_avail else "info",
            "score_impact": 0,
            "evidence": "Not listed in OpenPhish or PhishTank database." if is_avail else "OpenPhish / PhishTank feed unavailable."
        }
    }


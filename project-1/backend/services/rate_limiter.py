# Copyright (c) 2026 Jerald M Jolly, Bineesh Biju, Aston Mathew Felix, Adhul K R
# See LICENSE for details.
"""
CyberScape Centralized Rate Limiter
Thread-safe in-memory sliding window rate limiter for security scan endpoints.
Protects against automated abuse, scraping, and denial-of-service without external dependencies.
"""

import time
import threading
from functools import wraps
from flask import request, jsonify, current_app


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory rate limiter using sliding window counter per client key.
    """
    def __init__(self, default_limit: int = 60, default_window: int = 60):
        self.default_limit = default_limit
        self.default_window = default_window
        self._lock = threading.Lock()
        self._clients = {}  # key -> list of timestamps

    def is_allowed(self, client_key: str, limit: int = None, window: int = None) -> tuple[bool, int]:
        """
        Check if request is permitted.
        Returns: (allowed: bool, retry_after: int)
        """
        limit = limit or self.default_limit
        window = window or self.default_window
        now = time.time()
        cutoff = now - window

        with self._lock:
            # Clean old timestamps
            timestamps = self._clients.get(client_key, [])
            valid_timestamps = [t for t in timestamps if t > cutoff]

            if len(valid_timestamps) >= limit:
                # Calculate remaining wait time based on oldest valid timestamp
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + window - now))
                self._clients[client_key] = valid_timestamps
                return False, retry_after

            valid_timestamps.append(now)
            self._clients[client_key] = valid_timestamps
            return True, 0

    def reset(self):
        """Reset all rate limiter buckets (used in test fixtures)."""
        with self._lock:
            self._clients.clear()


# Global limiter instance
limiter = SlidingWindowRateLimiter(default_limit=60, default_window=60)


def get_client_identifier() -> str:
    """
    Extract reliable client identifier from request headers or socket.
    Prioritizes X-Forwarded-For if running behind a reverse proxy.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        if client_ip:
            return client_ip
    return request.remote_addr or "127.0.0.1"


def rate_limit(limit: int = 60, window_seconds: int = 60):
    """
    Flask route decorator that enforces rate limiting on API endpoints.
    Bypassed when TESTING=True in app config.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Bypass rate limit during automated test suite runs
            if current_app and current_app.config.get("TESTING"):
                return f(*args, **kwargs)

            client_key = f"{get_client_identifier()}:{request.endpoint}"
            allowed, retry_after = limiter.is_allowed(client_key, limit=limit, window=window_seconds)

            if not allowed:
                response = jsonify({
                    "error": f"Rate limit exceeded: too many requests. Please wait {retry_after} second{'s' if retry_after != 1 else ''} before running another scan.",
                    "retry_after": retry_after
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                return response

            return f(*args, **kwargs)
        return wrapper
    return decorator


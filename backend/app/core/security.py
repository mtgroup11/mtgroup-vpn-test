"""
MTGroup VPN Ultimate — Security Module
JWT tokens, password hashing, API key generation, and rate-limit logic.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt

from backend.app.core.config import settings
from backend.app.core.crypto_quantum import wrap_jwt_quantum, unwrap_jwt_quantum


# ---------------------------------------------------------------------------
# Password Hashing (bcrypt)
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    """Hash a plain-text password with bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# JWT Token Management
# ---------------------------------------------------------------------------

def create_access_token(
    data: dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a short-lived JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access", "iat": datetime.now(timezone.utc)})
    plain_token = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return wrap_jwt_quantum(plain_token)


def create_refresh_token(
    data: dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a long-lived JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode.update({"exp": expire, "type": "refresh", "iat": datetime.now(timezone.utc)})
    plain_token = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return wrap_jwt_quantum(plain_token)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a Quantum-Wrapped JWT token.
    Raises ValueError, jwt.ExpiredSignatureError or jwt.InvalidTokenError on failure.
    """
    try:
        plain_token = unwrap_jwt_quantum(token)
    except ValueError as e:
        raise jwt.InvalidTokenError("Failed to unwrap quantum token") from e
        
    return jwt.decode(
        plain_token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )


def verify_access_token(token: str) -> Optional[dict[str, Any]]:
    """Verify an access token and return its payload, or None if invalid."""
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def verify_refresh_token(token: str) -> Optional[dict[str, Any]]:
    """Verify a refresh token and return its payload, or None if invalid."""
    try:
        payload = decode_token(token)
        if payload.get("type") != "refresh":
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ---------------------------------------------------------------------------
# API Key Generation
# ---------------------------------------------------------------------------

def generate_api_key() -> str:
    """Generate a cryptographically secure API key for node authentication."""
    return secrets.token_urlsafe(48)


def generate_subscription_token() -> str:
    """Generate a unique subscription token."""
    return secrets.token_urlsafe(32)


def generate_short_id() -> str:
    """Generate a short ID for REALITY protocol."""
    return secrets.token_hex(4)


# ---------------------------------------------------------------------------
# HMAC Verification for Node-to-Panel Communication
# ---------------------------------------------------------------------------

def sign_payload(payload: bytes, key: str) -> str:
    """Create an HMAC-SHA256 signature for a payload."""
    return hmac.new(
        key.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()


def verify_signature(payload: bytes, signature: str, key: str) -> bool:
    """Verify an HMAC-SHA256 signature."""
    expected = sign_payload(payload, key)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Bounded in-memory maps
# ---------------------------------------------------------------------------
#
# All three trackers below are keyed by attacker-influenceable input (a
# client IP, or an IP+username pair). Without a cap, an attacker who sends
# requests from many distinct source IPs (real botnet, or spoofed
# X-Forwarded-For if a proxy trust boundary is ever misconfigured) grows
# these dicts forever — every one of them ships a `cleanup()` method, but
# nothing ever calls it, so in practice they are already unbounded today.
#
# `_evict_oldest_if_over_capacity` is checked on every write, not on a
# timer, since there is no background scheduler wired to these trackers —
# that is the only way to guarantee the bound holds under a sustained
# flood between now and whenever a periodic cleanup task might exist.
# This mirrors the *intent* (a hard ceiling + reclaim-oldest-first) of the
# bounded login-attempt map pattern used by other panels, reimplemented
# here for mtgroup's own dict-of-timestamps / dict-of-buckets shapes —
# not copied code.

def _evict_oldest_if_over_capacity(
    store: dict[str, Any],
    max_entries: int,
    last_activity: "Any",
) -> int:
    """Evict least-recently-active entries from `store` until it fits
    within `max_entries`. `last_activity(value)` returns the timestamp to
    rank by. Returns the number of entries evicted."""
    evicted = 0
    while len(store) > max_entries:
        oldest_key = min(store, key=lambda k: last_activity(store[k]))
        del store[oldest_key]
        evicted += 1
    return evicted


# ---------------------------------------------------------------------------
# In-Memory Rate Limiter (Token Bucket per IP)
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """
    Per-IP token bucket rate limiter.
    Each IP gets `max_tokens` tokens that refill at `refill_rate` tokens/second.

    `max_entries` bounds total memory use regardless of how many distinct
    IPs have ever made a request — see the module-level note above.

    Thread safety: a `threading.Lock` guards every read-modify-write of
    `_buckets`. This class is called from plain synchronous code (no
    `await` inside), so within a single asyncio worker there is never
    concurrent *coroutine* interleaving — but it can still be reached from
    more than one OS thread (e.g. a background watchdog thread alongside
    request-handling coroutines), and `dict` mutation from multiple
    threads without a lock is not safe: concurrent inserts/deletes during
    `min(store, ...)` iteration can raise `RuntimeError: dictionary keys
    changed during iteration`. A concurrency stress test
    (`backend/tests/test_security_bounds.py`) caught exactly this before
    the lock was added.
    """

    def __init__(
        self,
        max_tokens: int = 60,
        refill_rate: float = 1.0,
        max_entries: int = 50_000,
    ):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.max_entries = max_entries
        self._buckets: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def _get_bucket_locked(self, key: str) -> dict[str, float]:
        """Caller must hold `self._lock`."""
        now = time.monotonic()
        if key not in self._buckets:
            _evict_oldest_if_over_capacity(
                self._buckets, self.max_entries - 1, lambda v: v["last"]
            )
            self._buckets[key] = {"tokens": float(self.max_tokens), "last": now}
        bucket = self._buckets[key]
        elapsed = now - bucket["last"]
        bucket["tokens"] = min(
            self.max_tokens,
            bucket["tokens"] + elapsed * self.refill_rate,
        )
        bucket["last"] = now
        return bucket

    def is_allowed(self, key: str, cost: float = 1.0) -> bool:
        """Check if a request from `key` is allowed and consume a token."""
        with self._lock:
            bucket = self._get_bucket_locked(key)
            if bucket["tokens"] >= cost:
                bucket["tokens"] -= cost
                return True
            return False

    def remaining(self, key: str) -> float:
        """Return the number of remaining tokens for `key`."""
        with self._lock:
            return self._get_bucket_locked(key)["tokens"]

    def reset(self, key: str) -> None:
        """Reset the bucket for a specific key."""
        with self._lock:
            self._buckets.pop(key, None)

    def cleanup(self, max_age_seconds: float = 3600.0) -> int:
        """Remove stale bucket entries. Returns number of entries removed."""
        with self._lock:
            now = time.monotonic()
            stale_keys = [
                k for k, v in self._buckets.items()
                if now - v["last"] > max_age_seconds
            ]
            for k in stale_keys:
                del self._buckets[k]
            return len(stale_keys)


# ---------------------------------------------------------------------------
# Failed Login Tracker
# ---------------------------------------------------------------------------

class LoginAttemptTracker:
    """
    Tracks failed login attempts per IP.
    After `max_attempts` failures within `window_seconds`, the IP is flagged.

    `max_entries` bounds total memory use — see the module-level note above
    `_evict_oldest_if_over_capacity`.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        max_entries: int = 10_000,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_failure(self, ip: str) -> bool:
        """
        Record a failed login attempt. Returns True if the IP should be banned.
        """
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            is_new_key = ip not in self._attempts
            self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]
            self._attempts[ip].append(now)
            if is_new_key:
                _evict_oldest_if_over_capacity(
                    self._attempts, self.max_entries,
                    lambda times: times[-1] if times else 0.0,
                )
            return len(self._attempts[ip]) >= self.max_attempts

    def record_success(self, ip: str) -> None:
        """Clear failed attempts for an IP after successful login."""
        with self._lock:
            self._attempts.pop(ip, None)

    def get_attempts(self, ip: str) -> int:
        """Get current number of failed attempts for an IP."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]
            return len(self._attempts[ip])

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP has exceeded the attempt threshold."""
        return self.get_attempts(ip) >= self.max_attempts

    def cleanup(self) -> int:
        """Remove stale entries."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            stale = [
                ip for ip, times in self._attempts.items()
                if all(t <= cutoff for t in times)
            ]
            for ip in stale:
                del self._attempts[ip]
            return len(stale)


# ---------------------------------------------------------------------------
# Anomalous Handshake Tracker
# ---------------------------------------------------------------------------

class HandshakeTracker:
    """
    Tracks anomalous network handshakes per IP.
    After `max_anomalies` within `window_seconds`, the IP is flagged for kernel ban.

    `max_entries` bounds total memory use — see the module-level note above
    `_evict_oldest_if_over_capacity`.
    """

    def __init__(
        self,
        max_anomalies: int = 3,
        window_seconds: int = 300,
        max_entries: int = 10_000,
    ):
        self.max_anomalies = max_anomalies
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._anomalies: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_anomaly(self, ip: str) -> bool:
        """Record an anomalous handshake. Returns True if IP should be banned."""
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            is_new_key = ip not in self._anomalies
            self._anomalies[ip] = [t for t in self._anomalies[ip] if t > cutoff]
            self._anomalies[ip].append(now)
            if is_new_key:
                _evict_oldest_if_over_capacity(
                    self._anomalies, self.max_entries,
                    lambda times: times[-1] if times else 0.0,
                )
            return len(self._anomalies[ip]) >= self.max_anomalies

    def get_count(self, ip: str) -> int:
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self._anomalies[ip] = [t for t in self._anomalies[ip] if t > cutoff]
            return len(self._anomalies[ip])

    def cleanup(self) -> int:
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            stale = [
                ip for ip, times in self._anomalies.items()
                if all(t <= cutoff for t in times)
            ]
            for ip in stale:
                del self._anomalies[ip]
            return len(stale)


# ---------------------------------------------------------------------------
# Global Instances
# ---------------------------------------------------------------------------

rate_limiter = TokenBucketRateLimiter(
    max_tokens=settings.RATE_LIMIT_REQUESTS,
    refill_rate=settings.RATE_LIMIT_REQUESTS / settings.RATE_LIMIT_WINDOW_SECONDS,
)

login_tracker = LoginAttemptTracker(
    max_attempts=settings.MAX_FAILED_LOGINS,
    window_seconds=300,
)

handshake_tracker = HandshakeTracker(
    max_anomalies=settings.MAX_ANOMALOUS_HANDSHAKES,
    window_seconds=300,
)

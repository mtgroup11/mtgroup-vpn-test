"""
MTGroup VPN Ultimate — Security Module
JWT tokens, password hashing, API key generation, and rate-limit logic.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
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
# In-Memory Rate Limiter (Token Bucket per IP)
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """
    Per-IP token bucket rate limiter.
    Each IP gets `max_tokens` tokens that refill at `refill_rate` tokens/second.
    """

    def __init__(
        self,
        max_tokens: int = 60,
        refill_rate: float = 1.0,
    ):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self._buckets: dict[str, dict[str, float]] = {}

    def _get_bucket(self, key: str) -> dict[str, float]:
        now = time.monotonic()
        if key not in self._buckets:
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
        bucket = self._get_bucket(key)
        if bucket["tokens"] >= cost:
            bucket["tokens"] -= cost
            return True
        return False

    def remaining(self, key: str) -> float:
        """Return the number of remaining tokens for `key`."""
        return self._get_bucket(key)["tokens"]

    def reset(self, key: str) -> None:
        """Reset the bucket for a specific key."""
        self._buckets.pop(key, None)

    def cleanup(self, max_age_seconds: float = 3600.0) -> int:
        """Remove stale bucket entries. Returns number of entries removed."""
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
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def record_failure(self, ip: str) -> bool:
        """
        Record a failed login attempt. Returns True if the IP should be banned.
        """
        now = time.time()
        cutoff = now - self.window_seconds
        self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]
        self._attempts[ip].append(now)
        return len(self._attempts[ip]) >= self.max_attempts

    def record_success(self, ip: str) -> None:
        """Clear failed attempts for an IP after successful login."""
        self._attempts.pop(ip, None)

    def get_attempts(self, ip: str) -> int:
        """Get current number of failed attempts for an IP."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]
        return len(self._attempts[ip])

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP has exceeded the attempt threshold."""
        return self.get_attempts(ip) >= self.max_attempts

    def cleanup(self) -> int:
        """Remove stale entries."""
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
    """

    def __init__(
        self,
        max_anomalies: int = 3,
        window_seconds: int = 300,
    ):
        self.max_anomalies = max_anomalies
        self.window_seconds = window_seconds
        self._anomalies: dict[str, list[float]] = defaultdict(list)

    def record_anomaly(self, ip: str) -> bool:
        """Record an anomalous handshake. Returns True if IP should be banned."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._anomalies[ip] = [t for t in self._anomalies[ip] if t > cutoff]
        self._anomalies[ip].append(now)
        return len(self._anomalies[ip]) >= self.max_anomalies

    def get_count(self, ip: str) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        self._anomalies[ip] = [t for t in self._anomalies[ip] if t > cutoff]
        return len(self._anomalies[ip])

    def cleanup(self) -> int:
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

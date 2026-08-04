"""
MTGroup VPN Ultimate — Rate Limiter Middleware
Token bucket rate limiting with auto-ban via nftables integration.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from backend.app.core.config import settings
from backend.app.core.logging_config import audit_logger
from backend.app.core.security import rate_limiter

logger = logging.getLogger("mtgroup.api.rate_limiter")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Global rate limiting middleware.
    Applies token-bucket rate limiting to all incoming requests.
    Exempts subscription endpoints and health checks.
    """

    # Endpoints exempt from rate limiting
    EXEMPT_PATHS = frozenset({
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
    })

    # Subscription paths are rate-limited less aggressively
    SUBSCRIPTION_PREFIX = "/sub/"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path

        # Skip exempted paths
        if path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Subscription endpoints get a lighter rate limit (higher cost tolerance)
        cost = 0.5 if path.startswith(self.SUBSCRIPTION_PREFIX) else 1.0

        if not rate_limiter.is_allowed(client_ip, cost=cost):
            remaining = rate_limiter.remaining(client_ip)
            audit_logger.log_rate_limit(client_ip, path)
            logger.warning("Rate limit exceeded for IP %s on %s", client_ip, path)

            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please try again later.",
                    "retry_after": settings.RATE_LIMIT_WINDOW_SECONDS,
                },
                headers={
                    "Retry-After": str(settings.RATE_LIMIT_WINDOW_SECONDS),
                    "X-RateLimit-Remaining": str(int(remaining)),
                    "X-RateLimit-Limit": str(settings.RATE_LIMIT_REQUESTS),
                },
            )

        # Add rate limit headers to response
        response = await call_next(request)
        remaining = rate_limiter.remaining(client_ip)
        response.headers["X-RateLimit-Remaining"] = str(int(remaining))
        response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_REQUESTS)

        return response


class BannedIPMiddleware(BaseHTTPMiddleware):
    """
    Middleware that checks if the requesting IP is in the ban list.
    Uses ip_hash for zero-knowledge matching — never decrypts stored IPs.
    In-memory cache refreshed periodically from the database.
    """

    def __init__(self, app, db_session_factory=None):
        super().__init__(app)
        self._banned_ip_hashes: set[str] = set()
        self._last_refresh: float = 0
        self._refresh_interval: float = 30.0  # Refresh every 30 seconds
        self._db_session_factory = db_session_factory

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = request.client.host if request.client else "unknown"

        # Refresh ban list periodically
        now = time.monotonic()
        if now - self._last_refresh > self._refresh_interval:
            await self._refresh_ban_list()
            self._last_refresh = now

        # Compute hash of incoming IP and check against cached hashes
        from backend.app.core.crypto_quantum import hash_for_lookup
        ip_h = hash_for_lookup(client_ip)

        if ip_h in self._banned_ip_hashes:
            logger.warning("Blocked request from banned IP: %s", client_ip)
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied"},
            )

        return await call_next(request)

    async def _refresh_ban_list(self) -> None:
        """Refresh the in-memory ban hash list from the database."""
        if self._db_session_factory is None:
            return

        try:
            from sqlalchemy import select
            from backend.app.models import BannedIP

            async with self._db_session_factory() as session:
                now = datetime.now(timezone.utc)
                result = await session.execute(
                    select(BannedIP.ip_hash).where(
                        (BannedIP.expires_at.is_(None)) | (BannedIP.expires_at > now)
                    )
                )
                self._banned_ip_hashes = {row[0] for row in result.all()}
        except Exception as e:
            logger.error("Failed to refresh ban list: %s", e)

    def add_ban(self, ip: str) -> None:
        """Add an IP to the in-memory ban set immediately (via hash)."""
        from backend.app.core.crypto_quantum import hash_for_lookup
        self._banned_ip_hashes.add(hash_for_lookup(ip))

    def remove_ban(self, ip: str) -> None:
        """Remove an IP from the in-memory ban set (via hash)."""
        from backend.app.core.crypto_quantum import hash_for_lookup
        self._banned_ip_hashes.discard(hash_for_lookup(ip))


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Only set CSP for HTML responses
        content_type = response.headers.get("content-type", "")
        if "text/html" in content_type:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: blob:; "
                "connect-src 'self'"
            )

        return response

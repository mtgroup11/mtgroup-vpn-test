"""
MTGroup VPN Ultimate — Rate Limiter / Security Headers Middleware Test Suite
Tests backend/app/api/rate_limiter.py's three middleware classes against a
minimal Starlette app (not the full mtgroup app) so each is exercised in
isolation with a fresh `TokenBucketRateLimiter`, independent of any other
test's request volume.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.routing import Route

import pytest

from backend.app.api.rate_limiter import (
    BannedIPMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from backend.app.core.security import TokenBucketRateLimiter


async def _ok(request):
    return JSONResponse({"status": "ok"})


async def _html(request):
    return HTMLResponse("<html></html>")


def _make_app(*middleware_factories):
    app = Starlette(routes=[
        Route("/health", _ok),
        Route("/api/thing", _ok),
        Route("/sub/abc123", _ok),
        Route("/page", _html),
    ])
    for factory in middleware_factories:
        factory(app)
    return app


@pytest.fixture
def client_factory():
    async def _make(app):
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")
    return _make


class TestRateLimitMiddleware:
    @pytest.mark.asyncio
    async def test_exempt_path_is_never_throttled(self, monkeypatch, client_factory):
        import backend.app.api.rate_limiter as rl_module

        limiter = TokenBucketRateLimiter(max_tokens=1, refill_rate=0)
        monkeypatch.setattr(rl_module, "rate_limiter", limiter)

        app = _make_app(lambda a: a.add_middleware(RateLimitMiddleware))
        async with await client_factory(app) as ac:
            for _ in range(5):
                resp = await ac.get("/health")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_non_exempt_path_is_throttled_after_bucket_exhausted(self, monkeypatch, client_factory):
        import backend.app.api.rate_limiter as rl_module

        limiter = TokenBucketRateLimiter(max_tokens=2, refill_rate=0)
        monkeypatch.setattr(rl_module, "rate_limiter", limiter)

        app = _make_app(lambda a: a.add_middleware(RateLimitMiddleware))
        async with await client_factory(app) as ac:
            assert (await ac.get("/api/thing")).status_code == 200
            assert (await ac.get("/api/thing")).status_code == 200
            throttled = await ac.get("/api/thing")
            assert throttled.status_code == 429
            assert "Retry-After" in throttled.headers
            assert throttled.headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_subscription_paths_cost_half_a_token(self, monkeypatch, client_factory):
        import backend.app.api.rate_limiter as rl_module

        limiter = TokenBucketRateLimiter(max_tokens=1, refill_rate=0)
        monkeypatch.setattr(rl_module, "rate_limiter", limiter)

        app = _make_app(lambda a: a.add_middleware(RateLimitMiddleware))
        async with await client_factory(app) as ac:
            # 1 token, 0.5 cost each — two /sub/ requests should both succeed.
            assert (await ac.get("/sub/abc123")).status_code == 200
            assert (await ac.get("/sub/abc123")).status_code == 200
            assert (await ac.get("/sub/abc123")).status_code == 429

    @pytest.mark.asyncio
    async def test_successful_response_carries_rate_limit_headers(self, monkeypatch, client_factory):
        import backend.app.api.rate_limiter as rl_module

        # X-RateLimit-Limit reflects settings.RATE_LIMIT_REQUESTS, not the
        # limiter instance's own max_tokens — these are normally the same
        # value in production (the global `rate_limiter` singleton is
        # constructed from that same setting) but are two separate values
        # in this test, so assert against the setting the header actually
        # reads from.
        limiter = TokenBucketRateLimiter(max_tokens=5, refill_rate=0)
        monkeypatch.setattr(rl_module, "rate_limiter", limiter)

        app = _make_app(lambda a: a.add_middleware(RateLimitMiddleware))
        async with await client_factory(app) as ac:
            resp = await ac.get("/api/thing")
            assert resp.headers["X-RateLimit-Limit"] == str(rl_module.settings.RATE_LIMIT_REQUESTS)
            assert resp.headers["X-RateLimit-Remaining"] == "4"


class TestSecurityHeadersMiddleware:
    @pytest.mark.asyncio
    async def test_adds_standard_headers_to_every_response(self, client_factory):
        app = _make_app(lambda a: a.add_middleware(SecurityHeadersMiddleware))
        async with await client_factory(app) as ac:
            resp = await ac.get("/api/thing")
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert resp.headers["X-Frame-Options"] == "DENY"
            assert "Strict-Transport-Security" in resp.headers

    @pytest.mark.asyncio
    async def test_csp_only_added_for_html_responses(self, client_factory):
        app = _make_app(lambda a: a.add_middleware(SecurityHeadersMiddleware))
        async with await client_factory(app) as ac:
            html_resp = await ac.get("/page")
            json_resp = await ac.get("/api/thing")
            assert "Content-Security-Policy" in html_resp.headers
            assert "Content-Security-Policy" not in json_resp.headers


class TestBannedIPMiddleware:
    @pytest.mark.asyncio
    async def test_unbanned_ip_passes_through(self, client_factory):
        app = _make_app(lambda a: a.add_middleware(BannedIPMiddleware, db_session_factory=None))
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/api/thing")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_add_ban_and_remove_ban_round_trip(self):
        mw = BannedIPMiddleware(app=_make_app(), db_session_factory=None)
        mw.add_ban("203.0.113.9")
        from backend.app.core.crypto_quantum import hash_for_lookup

        assert hash_for_lookup("203.0.113.9") in mw._banned_ip_hashes
        mw.remove_ban("203.0.113.9")
        assert hash_for_lookup("203.0.113.9") not in mw._banned_ip_hashes

    @pytest.mark.asyncio
    async def test_refresh_ban_list_noop_without_db_factory(self):
        mw = BannedIPMiddleware(app=_make_app(), db_session_factory=None)
        await mw._refresh_ban_list()  # must not raise
        assert mw._banned_ip_hashes == set()

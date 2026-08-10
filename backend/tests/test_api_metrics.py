"""
MTGroup VPN Ultimate — Metrics API Test Suite
Covers GET /api/metrics/dashboard (previously mounted at the wrong path —
see api/metrics.py's prefix fix — meaning the frontend dashboard, which
already called /api/metrics/dashboard, always 404'd and silently fell
back to its client-side Math.random() simulation).
"""

from __future__ import annotations

import pytest


class TestDashboard:
    @pytest.mark.asyncio
    async def test_returns_expected_shape(self, client):
        resp = await client.get("/api/metrics/dashboard")
        assert resp.status_code == 200
        body = resp.json()
        assert "risk_score" in body
        assert 0 <= body["risk_score"] <= 100

    @pytest.mark.asyncio
    async def test_no_auth_required(self, client):
        # Matches the endpoint's actual dependency list (none) — the
        # panel dashboard polls this without a bearer token today.
        resp = await client.get("/api/metrics/dashboard")
        assert resp.status_code != 401
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_still_requires_stealth_token(self, client):
        no_stealth = client.headers.copy()
        no_stealth.pop("X-Stealth-Token", None)
        resp = await client.get("/api/metrics/dashboard", headers={"X-Stealth-Token": "wrong-token"})
        assert resp.status_code == 404  # stealth_middleware disguises itself as a generic 404

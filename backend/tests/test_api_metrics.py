"""
MTGroup VPN Ultimate — Metrics API Test Suite
Covers GET /api/metrics/dashboard (previously mounted at the wrong path —
see api/metrics.py's prefix fix — meaning the frontend dashboard, which
already called /api/metrics/dashboard, always 404'd and silently fell
back to its client-side Math.random() simulation), the pure risk/quality
scoring functions, the autonomous-shield trigger, and the WebSocket
ConnectionManager's connect/disconnect/broadcast lifecycle.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.api.metrics import (
    ConnectionManager,
    calculate_connection_quality,
    calculate_system_risk_score,
    trigger_autonomous_shield,
)


class TestCalculateSystemRiskScore:
    def test_zero_inputs_is_zero_low(self):
        score, status = calculate_system_risk_score(0, 0, 10.0, 10.0, 0.0)
        assert score == 0
        assert status == "Low"

    def test_ebpf_bans_add_ten_per_fifty(self):
        score, _ = calculate_system_risk_score(150, 0, 10.0, 10.0, 0.0)
        assert score == 30  # 150 // 50 * 10

    def test_honeypot_triggers_add_fifteen_each(self):
        score, _ = calculate_system_risk_score(0, 2, 10.0, 10.0, 0.0)
        assert score == 30

    def test_cpu_saturation_adds_twenty(self):
        score, _ = calculate_system_risk_score(0, 0, 85.0, 10.0, 0.0)
        assert score == 20

    def test_ram_saturation_adds_twenty(self):
        score, _ = calculate_system_risk_score(0, 0, 10.0, 85.0, 0.0)
        assert score == 20

    def test_failed_handshake_rate_adds_twenty_five(self):
        score, _ = calculate_system_risk_score(0, 0, 10.0, 10.0, 15.0)
        assert score == 25

    def test_score_caps_at_one_hundred(self):
        score, status = calculate_system_risk_score(1000, 10, 95.0, 95.0, 50.0)
        assert score == 100
        assert status == "Critical"

    def test_medium_band(self):
        # honeypot_triggers=2 -> 30, which falls in (25, 60] -> Medium
        score, status = calculate_system_risk_score(0, 2, 10.0, 10.0, 0.0)
        assert status == "Medium"

    def test_low_band_boundary(self):
        # 25 is still Low (<=25)
        score, status = calculate_system_risk_score(0, 0, 85.0, 10.0, 0.0)
        assert score == 20
        assert status == "Low"


class TestCalculateConnectionQuality:
    def test_perfect_connection_is_100(self):
        assert calculate_connection_quality(latency_ms=50.0, packet_loss_pct=0.0, handshake_success_rate=100.0) == 100

    def test_high_latency_penalized_and_capped(self):
        # (500-100)*0.1 = 40, capped at 30
        score = calculate_connection_quality(latency_ms=500.0, packet_loss_pct=0.0, handshake_success_rate=100.0)
        assert score == 70

    def test_packet_loss_penalized_and_capped(self):
        # 20% * 4 = 80, capped at 40
        score = calculate_connection_quality(latency_ms=50.0, packet_loss_pct=20.0, handshake_success_rate=100.0)
        assert score == 60

    def test_handshake_failure_penalized(self):
        score = calculate_connection_quality(latency_ms=50.0, packet_loss_pct=0.0, handshake_success_rate=80.0)
        assert score == 80

    def test_score_never_goes_below_zero(self):
        score = calculate_connection_quality(latency_ms=1000.0, packet_loss_pct=100.0, handshake_success_rate=0.0)
        assert score == 0


class TestTriggerAutonomousShield:
    @pytest.mark.asyncio
    async def test_runs_without_raising_and_logs_critical(self, caplog):
        import logging
        with caplog.at_level(logging.CRITICAL, logger="mtgroup.api.metrics"):
            await trigger_autonomous_shield(90)
        assert any("AUTONOMOUS SHIELD" in r.message for r in caplog.records)


class TestConnectionManager:
    @pytest.fixture
    def manager(self):
        return ConnectionManager()

    def _make_ws(self):
        ws = MagicMock()
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        return ws

    @pytest.mark.asyncio
    async def test_connect_accepts_and_tracks_websocket(self, manager):
        ws = self._make_ws()
        await manager.connect(ws)
        ws.accept.assert_awaited_once()
        assert ws in manager.active_connections

    @pytest.mark.asyncio
    async def test_first_connect_starts_background_task(self, manager):
        ws = self._make_ws()
        await manager.connect(ws)
        assert manager._is_running is True
        assert manager._background_task is not None
        manager.disconnect(ws)

    @pytest.mark.asyncio
    async def test_second_connect_does_not_spawn_a_second_task(self, manager):
        ws1, ws2 = self._make_ws(), self._make_ws()
        await manager.connect(ws1)
        task = manager._background_task
        await manager.connect(ws2)
        assert manager._background_task is task
        manager.disconnect(ws1)
        manager.disconnect(ws2)

    @pytest.mark.asyncio
    async def test_disconnect_removes_connection(self, manager):
        ws = self._make_ws()
        await manager.connect(ws)
        manager.disconnect(ws)
        assert ws not in manager.active_connections

    @pytest.mark.asyncio
    async def test_disconnect_stops_background_task_when_last_client_leaves(self, manager):
        ws = self._make_ws()
        await manager.connect(ws)
        task = manager._background_task
        manager.disconnect(ws)
        assert manager._is_running is False
        # cancel() was requested synchronously; the task itself only
        # transitions to cancelled once the event loop gets a chance to
        # run it, which happens on the next await.
        assert task.cancelling() > 0
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert task.cancelled()

    def test_disconnect_of_unknown_websocket_is_a_noop(self, manager):
        ws = self._make_ws()
        manager.disconnect(ws)  # never connected — must not raise
        assert manager.active_connections == []

    @pytest.mark.asyncio
    async def test_stream_metrics_broadcasts_to_all_connections(self, manager, monkeypatch):
        io_before = MagicMock(bytes_recv=1000, bytes_sent=500)
        io_after = MagicMock(bytes_recv=1500, bytes_sent=800)
        monkeypatch.setattr(
            "backend.app.api.metrics.psutil.net_io_counters",
            MagicMock(side_effect=[io_before, io_after]),
        )
        monkeypatch.setattr("backend.app.api.metrics.psutil.cpu_percent", MagicMock(return_value=5.0))
        monkeypatch.setattr(
            "backend.app.api.metrics.psutil.virtual_memory", MagicMock(return_value=MagicMock(percent=10.0))
        )
        monkeypatch.setattr(
            "backend.app.api.metrics.xdp_loader.get_stats",
            MagicMock(return_value={"active_bans": 0, "simulated": True}),
        )

        ws_good = self._make_ws()
        ws_bad = self._make_ws()
        ws_bad.send_text = AsyncMock(side_effect=RuntimeError("connection reset"))
        manager.active_connections = [ws_good, ws_bad]
        manager._is_running = True

        # Stop the loop after one iteration by flipping is_running off once
        # sleep is hit, instead of relying on real 1-second waits.
        async def _one_shot_sleep(*args, **kwargs):
            manager._is_running = False

        monkeypatch.setattr("backend.app.api.metrics.asyncio.sleep", _one_shot_sleep)

        await manager._stream_metrics()

        ws_good.send_text.assert_awaited_once()
        ws_bad.send_text.assert_awaited_once()
        # The failing client should have been cleaned up by the broadcast loop.
        assert ws_bad not in manager.active_connections
        assert ws_good in manager.active_connections

    @pytest.mark.asyncio
    async def test_stream_metrics_survives_unexpected_exception(self, manager, monkeypatch):
        # First call is the unprotected `last_io = psutil.net_io_counters()`
        # before the loop's try/except even starts; only the *second* call
        # (inside the loop) is meant to be caught by its except-block.
        monkeypatch.setattr(
            "backend.app.api.metrics.psutil.net_io_counters",
            MagicMock(side_effect=[MagicMock(bytes_recv=0, bytes_sent=0), RuntimeError("boom")]),
        )

        async def _one_shot_sleep(*args, **kwargs):
            manager._is_running = False

        monkeypatch.setattr("backend.app.api.metrics.asyncio.sleep", _one_shot_sleep)

        manager._is_running = True
        manager.active_connections = [self._make_ws()]
        await manager._stream_metrics()  # must not raise despite psutil erroring inside the loop


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

    @pytest.mark.asyncio
    async def test_ebpf_error_status_surfaces_in_response(self, client, monkeypatch):
        monkeypatch.setattr(
            "backend.app.api.metrics.xdp_loader.get_stats",
            MagicMock(return_value={"error": "BPF map read failed", "simulated": True}),
        )
        resp = await client.get("/api/metrics/dashboard")
        assert resp.status_code == 200
        assert resp.json()["ebpf_status"] == "Error: BPF map read failed"

    @pytest.mark.asyncio
    async def test_net_connections_permission_error_falls_back_to_zero_active_users(self, client, monkeypatch):
        monkeypatch.setattr(
            "backend.app.api.metrics.psutil.net_connections",
            MagicMock(side_effect=PermissionError("not allowed")),
        )
        resp = await client.get("/api/metrics/dashboard")
        assert resp.status_code == 200
        assert resp.json()["active_users"] == 0

    @pytest.mark.asyncio
    async def test_critical_risk_score_triggers_autonomous_shield(self, client, monkeypatch):
        # active_bans=400 -> (400 // 50) * 10 = 80 risk points on its own,
        # already over the >75 threshold that fires trigger_autonomous_shield.
        monkeypatch.setattr(
            "backend.app.api.metrics.xdp_loader.get_stats",
            MagicMock(return_value={"active_bans": 400, "simulated": False}),
        )
        shield_mock = AsyncMock()
        monkeypatch.setattr("backend.app.api.metrics.trigger_autonomous_shield", shield_mock)

        resp = await client.get("/api/metrics/dashboard")
        assert resp.status_code == 200
        assert resp.json()["risk_score"] > 75
        shield_mock.assert_awaited_once_with(resp.json()["risk_score"])

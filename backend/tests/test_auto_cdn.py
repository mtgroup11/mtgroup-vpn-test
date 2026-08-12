"""
MTGroup VPN Ultimate — Auto-CDN & Smart SNI Engine Test Suite
Covers the start/stop lifecycle, the run loop invoking both health-check
hooks each cycle, `_probe_tls`'s real-vs-failed TLS handshake outcome
(with the actual socket/TLS I/O mocked out — no real network access in
this suite), and `_check_sni_health`/`_manage_auto_cdn`'s node-probing
and fallback-selection logic.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.core.auto_cdn import SingularityAutoCDN


@pytest.fixture
def engine():
    return SingularityAutoCDN(session_factory=lambda: None)


class TestStartStop:
    @pytest.mark.asyncio
    async def test_start_spawns_loop_task_and_is_idempotent(self, engine):
        await engine.start()
        assert engine.is_running is True
        task = engine._task
        assert task is not None and not task.done()

        await engine.start()
        assert engine._task is task

        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_loop_task(self, engine):
        await engine.start()
        task = engine._task
        await engine.stop()
        assert engine.is_running is False
        assert task.done()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_a_noop(self, engine):
        await engine.stop()
        assert engine.is_running is False


class TestRunLoop:
    """
    Drives `_run_loop` directly (not via `start()`/a background task) so
    each test controls exactly one iteration deterministically instead of
    racing the event loop with `asyncio.sleep(0)`.
    """

    @pytest.mark.asyncio
    async def test_each_cycle_calls_both_health_checks(self, engine, monkeypatch):
        monkeypatch.setattr(engine, "_check_sni_health", AsyncMock())
        monkeypatch.setattr(engine, "_manage_auto_cdn", AsyncMock())

        async def _stop_after_first_sleep(*args, **kwargs):
            engine.is_running = False

        monkeypatch.setattr(asyncio, "sleep", AsyncMock(side_effect=_stop_after_first_sleep))

        engine.is_running = True
        await engine._run_loop()

        engine._check_sni_health.assert_awaited_once()
        engine._manage_auto_cdn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_exception_in_cycle_is_caught_and_logged(self, engine, monkeypatch):
        monkeypatch.setattr(engine, "_check_sni_health", AsyncMock(side_effect=RuntimeError("boom")))
        monkeypatch.setattr(engine, "_manage_auto_cdn", AsyncMock())

        async def _stop_after_first_sleep(*args, **kwargs):
            engine.is_running = False

        monkeypatch.setattr(asyncio, "sleep", AsyncMock(side_effect=_stop_after_first_sleep))

        engine.is_running = True
        await engine._run_loop()  # should not raise despite the cycle erroring
        engine._manage_auto_cdn.assert_not_awaited()  # exception short-circuits the rest of the cycle


def _fake_session_factory(nodes):
    """A `session_factory()` whose session.execute().scalars().all() returns `nodes`."""
    session = AsyncMock()
    session.execute.return_value = MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=nodes))))

    class _Ctx:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *exc):
            return False

    return lambda: _Ctx()


class TestProbeTls:
    @pytest.mark.asyncio
    async def test_clean_handshake_returns_true(self, engine, monkeypatch):
        writer = MagicMock()
        writer.wait_closed = AsyncMock()

        async def _fake_open_connection(host, port, ssl, server_hostname):
            return MagicMock(), writer

        monkeypatch.setattr("backend.app.core.auto_cdn.asyncio.open_connection", _fake_open_connection)

        assert await engine._probe_tls("example.com", 443, sni="example.com") is True
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_connection_error_returns_false(self, engine, monkeypatch):
        async def _fake_open_connection(host, port, ssl, server_hostname):
            raise ConnectionResetError("reset by peer")  # the actual DPI-interference signature

        monkeypatch.setattr("backend.app.core.auto_cdn.asyncio.open_connection", _fake_open_connection)

        assert await engine._probe_tls("blocked.example.com") is False

    @pytest.mark.asyncio
    async def test_timeout_returns_false(self, engine, monkeypatch):
        async def _fake_open_connection(host, port, ssl, server_hostname):
            await asyncio.sleep(100)  # never actually reached; wait_for times out first

        monkeypatch.setattr("backend.app.core.auto_cdn.asyncio.open_connection", _fake_open_connection)
        monkeypatch.setattr("backend.app.core.auto_cdn.SNI_CHECK_TIMEOUT_SECONDS", 0.01)

        assert await engine._probe_tls("slow.example.com") is False


def _make_node(**overrides):
    from types import SimpleNamespace

    defaults = dict(id=1, name="node-1", address="10.0.0.5", port=443, sni="camouflage.example.com", is_active=True)
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestCheckSniHealth:
    @pytest.mark.asyncio
    async def test_probes_every_active_node_with_an_sni(self, engine, monkeypatch):
        nodes = [_make_node(id=1, sni="a.example.com"), _make_node(id=2, sni="b.example.com")]
        engine.session_factory = _fake_session_factory(nodes)

        probed = []

        async def _fake_probe(host, port=443, sni=None):
            probed.append((host, port, sni))
            return True

        monkeypatch.setattr(engine, "_probe_tls", _fake_probe)

        await engine._check_sni_health()

        assert probed == [("10.0.0.5", 443, "a.example.com"), ("10.0.0.5", 443, "b.example.com")]
        assert engine._sni_healthy == {"a.example.com": True, "b.example.com": True}

    @pytest.mark.asyncio
    async def test_skips_nodes_without_an_sni(self, engine, monkeypatch):
        nodes = [_make_node(sni=None)]
        engine.session_factory = _fake_session_factory(nodes)

        probe = AsyncMock()
        monkeypatch.setattr(engine, "_probe_tls", probe)

        await engine._check_sni_health()

        probe.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_records_unhealthy_result(self, engine, monkeypatch):
        nodes = [_make_node(sni="blocked.example.com")]
        engine.session_factory = _fake_session_factory(nodes)
        monkeypatch.setattr(engine, "_probe_tls", AsyncMock(return_value=False))

        await engine._check_sni_health()

        assert engine._sni_healthy == {"blocked.example.com": False}

    @pytest.mark.asyncio
    async def test_noop_without_a_session_factory(self, engine):
        engine.session_factory = None
        await engine._check_sni_health()  # must not raise
        assert engine._sni_healthy == {}


class TestManageAutoCdn:
    @pytest.mark.asyncio
    async def test_noop_when_cdn_disabled(self, engine, monkeypatch):
        monkeypatch.setattr("backend.app.core.auto_cdn.settings.CDN_ENABLED", False)
        engine._sni_healthy = {"x.example.com": False}
        probe = AsyncMock()
        monkeypatch.setattr(engine, "_probe_tls", probe)

        await engine._manage_auto_cdn()

        probe.assert_not_awaited()
        assert engine.current_cdn_target is None

    @pytest.mark.asyncio
    async def test_noop_when_nothing_unhealthy(self, engine, monkeypatch):
        monkeypatch.setattr("backend.app.core.auto_cdn.settings.CDN_ENABLED", True)
        engine._sni_healthy = {"x.example.com": True}
        probe = AsyncMock()
        monkeypatch.setattr(engine, "_probe_tls", probe)

        await engine._manage_auto_cdn()

        probe.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_selects_first_reachable_fallback_candidate(self, engine, monkeypatch):
        monkeypatch.setattr("backend.app.core.auto_cdn.settings.CDN_ENABLED", True)
        monkeypatch.setattr(
            "backend.app.core.auto_cdn.FALLBACK_CDN_CANDIDATES", ["1.2.3.4", "5.6.7.8"],
        )
        engine._sni_healthy = {"x.example.com": False}

        async def _fake_probe(host, port=443, sni=None):
            return host == "5.6.7.8"  # first candidate unreachable, second works

        monkeypatch.setattr(engine, "_probe_tls", _fake_probe)

        await engine._manage_auto_cdn()

        assert engine.current_cdn_target == "5.6.7.8"

    @pytest.mark.asyncio
    async def test_clears_target_when_all_candidates_unreachable(self, engine, monkeypatch):
        monkeypatch.setattr("backend.app.core.auto_cdn.settings.CDN_ENABLED", True)
        monkeypatch.setattr("backend.app.core.auto_cdn.FALLBACK_CDN_CANDIDATES", ["1.2.3.4"])
        engine._sni_healthy = {"x.example.com": False}
        engine.current_cdn_target = "stale.candidate"
        monkeypatch.setattr(engine, "_probe_tls", AsyncMock(return_value=False))

        await engine._manage_auto_cdn()

        assert engine.current_cdn_target is None

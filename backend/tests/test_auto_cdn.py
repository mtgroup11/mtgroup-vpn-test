"""
MTGroup VPN Ultimate — Auto-CDN & Smart SNI Engine Test Suite
`_check_sni_health` / `_manage_auto_cdn` are unimplemented stubs (`pass`)
per the module docstring's "To be implemented fully" — nothing to assert
there. This covers the real logic that exists today: the start/stop
lifecycle and the run loop invoking both stub hooks each cycle.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

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

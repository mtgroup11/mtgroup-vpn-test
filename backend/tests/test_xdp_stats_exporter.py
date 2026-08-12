"""
MTGroup VPN Ultimate — XDP Stats Exporter Test Suite
Covers the start/stop lifecycle, the write-loop invoking _write_stats
each cycle, and _write_stats' own translation from XDPLoader.get_stats()
into the {total_dropped, active_v4, active_v6} schema cli.py and the
Telegram bot actually read — with real file I/O against a tmp_path (no
mocking needed, it's cheap and this is exactly what the regression would
be: does a real, readable file land on disk).
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.core.xdp_stats_exporter import XDPStatsExporter


@pytest.fixture
def loader():
    return MagicMock()


class TestStartStop:
    @pytest.mark.asyncio
    async def test_start_spawns_loop_task_and_is_idempotent(self, loader):
        exporter = XDPStatsExporter(loader)
        await exporter.start()
        assert exporter.is_running is True
        task = exporter._task
        assert task is not None and not task.done()

        await exporter.start()
        assert exporter._task is task

        await exporter.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_loop_task(self, loader):
        exporter = XDPStatsExporter(loader)
        await exporter.start()
        task = exporter._task
        await exporter.stop()
        assert exporter.is_running is False
        assert task.done()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_a_noop(self, loader):
        exporter = XDPStatsExporter(loader)
        await exporter.stop()
        assert exporter.is_running is False


class TestRunLoop:
    @pytest.mark.asyncio
    async def test_each_cycle_writes_stats(self, loader, monkeypatch):
        exporter = XDPStatsExporter(loader)
        monkeypatch.setattr(exporter, "_write_stats", MagicMock())

        async def _stop_after_first_sleep(*a, **kw):
            exporter.is_running = False

        monkeypatch.setattr(asyncio, "sleep", AsyncMock(side_effect=_stop_after_first_sleep))

        exporter.is_running = True
        await exporter._run_loop()

        exporter._write_stats.assert_called_once()

    @pytest.mark.asyncio
    async def test_exception_in_a_cycle_does_not_kill_the_loop(self, loader, monkeypatch):
        exporter = XDPStatsExporter(loader)
        monkeypatch.setattr(exporter, "_write_stats", MagicMock(side_effect=RuntimeError("disk full")))

        sleep_calls = 0

        async def _stop_after_second_sleep(*a, **kw):
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls >= 2:
                exporter.is_running = False

        monkeypatch.setattr(asyncio, "sleep", AsyncMock(side_effect=_stop_after_second_sleep))

        exporter.is_running = True
        await exporter._run_loop()  # must not raise

        assert exporter._write_stats.call_count == 2


class TestWriteStats:
    def test_writes_readable_json_with_expected_keys(self, loader, tmp_path):
        stats_path = str(tmp_path / "xdp_stats.json")
        loader.get_stats.return_value = {"total_dropped": 42, "active_bans": 3, "simulated": False}
        exporter = XDPStatsExporter(loader, stats_path=stats_path)

        exporter._write_stats()

        written = json.loads((tmp_path / "xdp_stats.json").read_text(encoding="utf-8"))
        assert written == {"total_dropped": 42, "active_v4": 3, "active_v6": 0}

    def test_leaves_no_temp_file_behind(self, loader, tmp_path):
        stats_path = str(tmp_path / "xdp_stats.json")
        loader.get_stats.return_value = {"total_dropped": 1, "active_bans": 1, "simulated": False}
        exporter = XDPStatsExporter(loader, stats_path=stats_path)

        exporter._write_stats()

        assert [p.name for p in tmp_path.iterdir()] == ["xdp_stats.json"]

    def test_creates_missing_parent_directory(self, loader, tmp_path):
        stats_path = str(tmp_path / "nested" / "dir" / "xdp_stats.json")
        loader.get_stats.return_value = {"total_dropped": 0, "active_bans": 0, "simulated": False}
        exporter = XDPStatsExporter(loader, stats_path=stats_path)

        exporter._write_stats()  # must not raise

        assert (tmp_path / "nested" / "dir" / "xdp_stats.json").exists()

    def test_never_writes_fabricated_simulated_numbers(self, loader, tmp_path):
        """
        XDPLoader falls back to random numbers when BCC isn't importable,
        independent of whether the operator actually enabled eBPF. An
        operator reading this file has no way to tell fake numbers from
        real ones, so this must never persist them — the file staying
        absent is the honest outcome (both readers already degrade
        gracefully to zero).
        """
        stats_path = str(tmp_path / "xdp_stats.json")
        loader.get_stats.return_value = {"total_dropped": 4321, "active_bans": 12, "simulated": True}
        exporter = XDPStatsExporter(loader, stats_path=stats_path)

        exporter._write_stats()

        assert not (tmp_path / "xdp_stats.json").exists()

    def test_overwrites_a_previous_snapshot(self, loader, tmp_path):
        stats_path = str(tmp_path / "xdp_stats.json")
        exporter = XDPStatsExporter(loader, stats_path=stats_path)

        loader.get_stats.return_value = {"total_dropped": 1, "active_bans": 1, "simulated": False}
        exporter._write_stats()
        loader.get_stats.return_value = {"total_dropped": 99, "active_bans": 5, "simulated": False}
        exporter._write_stats()

        written = json.loads((tmp_path / "xdp_stats.json").read_text(encoding="utf-8"))
        assert written["total_dropped"] == 99

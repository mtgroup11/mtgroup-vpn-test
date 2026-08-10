"""
MTGroup VPN Ultimate — Multi-Port Hopping Engine Test Suite
Tests backend/app/generators/port_hopper.py's PortHopper (pure, in-memory
pool math — no I/O) and AsyncPortHoppingEngine's lifecycle and node-sync
loop (DB session factory, orchestrator, and eBPF maps all mocked; the
6-hour sleep is patched so the loop runs one deterministic iteration).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.generators.port_hopper import AsyncPortHoppingEngine, PortHopper


def _hopper(**overrides) -> PortHopper:
    defaults = dict(
        low_ports=[80, 443],
        high_port_start=50000,
        high_port_end=50100,
        hop_interval_sec=1,
        high_port_pool_size=10,
    )
    defaults.update(overrides)
    return PortHopper(**defaults)


class TestPoolConstruction:
    def test_high_pool_respects_requested_size(self):
        h = _hopper(high_port_pool_size=7)
        assert len(h._high_port_pool) == 7

    def test_high_pool_ports_are_within_configured_range(self):
        h = _hopper()
        assert all(50000 <= p <= 50100 for p in h._high_port_pool)

    def test_high_pool_has_no_duplicates(self):
        h = _hopper(high_port_pool_size=50)
        assert len(set(h._high_port_pool)) == len(h._high_port_pool)

    def test_combined_pool_contains_every_low_port(self):
        h = _hopper(low_ports=[80, 443, 8080])
        for port in (80, 443, 8080):
            assert port in h._combined_pool

    def test_combined_pool_interleaves_three_high_ports_per_low_port(self):
        h = _hopper(low_ports=[80, 443], high_port_pool_size=10)
        # Layout is [low, high, high, high, low, high, high, high, ...rest]
        assert h._combined_pool[0] == 80
        assert h._combined_pool[4] == 443
        assert all(p not in (80, 443) for p in h._combined_pool[1:4])

    def test_combined_pool_wraps_when_high_pool_is_smaller_than_needed(self):
        # 3 low ports need 9 interleaved high ports but only 2 exist —
        # the iterator must restart rather than raise StopIteration.
        h = _hopper(low_ports=[80, 443, 8080], high_port_pool_size=2)
        assert len(h._combined_pool) >= 12

    def test_initial_port_is_first_low_port(self):
        h = _hopper(low_ports=[8443, 443])
        assert h._current_port == 8443

    def test_explicit_empty_low_ports_is_ignored_in_favour_of_config(self):
        # Note the asymmetry in PortHopper.__init__: high_port_start/end and
        # hop_interval_sec use `is not None`, but low_ports uses `or` — so an
        # explicitly-passed empty list is falsy and silently replaced by
        # settings.low_port_list. Documented here rather than "fixed" because
        # nothing in the codebase passes [], and changing it would be a
        # behaviour change with no observed bug behind it.
        h = _hopper(low_ports=[])
        assert h.low_ports != []

    def test_falls_back_to_443_when_config_has_no_low_ports(self, monkeypatch):
        # The only way low_ports actually ends up empty is an empty
        # PORT_POOL_LOW in config — that's the path the `else 443` fallback
        # in __init__ exists for.
        from backend.app.core.config import settings

        monkeypatch.setattr(type(settings), "low_port_list", property(lambda _self: []))
        h = PortHopper(high_port_start=50000, high_port_end=50100, hop_interval_sec=1, high_port_pool_size=10)
        assert h.low_ports == []
        assert h._current_port == 443


class TestHopping:
    def test_force_hop_changes_index_and_returns_new_port(self):
        h = _hopper()
        before = h._current_index
        new_port = h.force_hop()
        assert h._current_index == before + 1
        assert new_port == h._combined_pool[h._current_index]

    def test_force_hop_wraps_around_the_pool(self):
        h = _hopper()
        h._current_index = len(h._combined_pool) - 1
        h.force_hop()
        assert h._current_index == 0

    def test_get_current_port_does_not_hop_before_interval_elapses(self):
        h = _hopper(hop_interval_sec=3600)
        first = h.get_current_port()
        second = h.get_current_port()
        assert first == second

    def test_get_current_port_hops_once_interval_has_elapsed(self, monkeypatch):
        h = _hopper(hop_interval_sec=10)
        start = h._last_hop_time
        monkeypatch.setattr(
            "backend.app.generators.port_hopper.time.monotonic", lambda: start + 11
        )
        assert h.get_current_port() != h._combined_pool[0] or h._current_index == 1
        assert h._current_index == 1


class TestClientPortList:
    def test_returns_requested_count(self):
        h = _hopper()
        assert len(h.get_port_list_for_client(count=5)) == 5

    def test_starts_from_the_current_index(self):
        h = _hopper()
        h._current_index = 2
        ports = h.get_port_list_for_client(count=3)
        assert ports == [h._combined_pool[2], h._combined_pool[3], h._combined_pool[4]]

    def test_wraps_around_the_end_of_the_pool(self):
        h = _hopper()
        h._current_index = len(h._combined_pool) - 1
        ports = h.get_port_list_for_client(count=3)
        assert ports[1] == h._combined_pool[0]

    def test_count_larger_than_pool_returns_whole_pool(self):
        h = _hopper()
        ports = h.get_port_list_for_client(count=10_000)
        assert ports == list(h._combined_pool)


class TestPortRangeString:
    def test_formats_low_ports_and_high_range(self):
        h = _hopper(low_ports=[80, 443], high_port_start=50000, high_port_end=65000)
        assert h.get_port_range_string() == "80,443,50000-65000"


class TestNftablesPortSet:
    def test_collapses_consecutive_ports_into_ranges(self):
        h = _hopper()
        h.low_ports = [80]
        h._high_port_pool = [50000, 50001, 50002, 50010]
        result = h.get_nftables_port_set()
        assert result == "{ 80, 50000-50002, 50010 }"

    def test_single_isolated_ports_are_listed_individually(self):
        h = _hopper()
        h.low_ports = [80, 443]
        h._high_port_pool = [50000]
        assert h.get_nftables_port_set() == "{ 80, 443, 50000 }"

    def test_deduplicates_overlapping_low_and_high_ports(self):
        h = _hopper()
        h.low_ports = [8080]
        h._high_port_pool = [8080, 8081]
        assert h.get_nftables_port_set() == "{ 8080-8081 }"


class TestRefreshHighPorts:
    def test_regenerates_pool_and_resets_position(self):
        h = _hopper()
        h.force_hop()
        h.force_hop()
        assert h._current_index != 0

        h.refresh_high_ports()

        assert h._current_index == 0
        assert h._current_port == h._combined_pool[0]
        assert len(h._high_port_pool) == h.high_port_pool_size


class TestGetStats:
    def test_reports_pool_state(self):
        h = _hopper(low_ports=[80, 443], high_port_pool_size=10)
        stats = h.get_stats()
        assert stats["current_port"] == h._current_port
        assert stats["low_ports"] == [80, 443]
        assert stats["high_port_pool_size"] == 10
        assert stats["total_ports"] == len(h._combined_pool)
        assert stats["high_port_range"] == "50000-50100"


# ---------------------------------------------------------------------------
# AsyncPortHoppingEngine
# ---------------------------------------------------------------------------

def _session_factory_with(session):
    class _Ctx:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *exc):
            return False

    return lambda: _Ctx()


class TestAsyncEngineLifecycle:
    @pytest.mark.asyncio
    async def test_start_spawns_worker_and_is_idempotent(self):
        engine = AsyncPortHoppingEngine(db_session_factory=MagicMock())
        await engine.start()
        task = engine._worker_task
        assert engine._is_running is True
        assert task is not None

        await engine.start()
        assert engine._worker_task is task

        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_worker(self):
        engine = AsyncPortHoppingEngine(db_session_factory=MagicMock())
        await engine.start()
        task = engine._worker_task
        await engine.stop()
        assert engine._is_running is False
        assert task.done()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_a_noop(self):
        engine = AsyncPortHoppingEngine(db_session_factory=MagicMock())
        await engine.stop()
        assert engine._is_running is False

    @pytest.mark.asyncio
    async def test_start_seeds_ebpf_maps_when_bpf_present(self):
        engine = AsyncPortHoppingEngine(db_session_factory=MagicMock())
        fake_map = MagicMock()
        fake_map.Key = MagicMock(return_value="k")
        fake_map.Leaf = MagicMock(return_value="v")
        engine._bpf = MagicMock()
        engine._bpf.get_table.return_value = fake_map

        await engine.start()
        await engine.stop()

        # Both active_port_map and honeypot_port_map are looked up and seeded.
        looked_up = {c.args[0] for c in engine._bpf.get_table.call_args_list}
        assert looked_up == {"active_port_map", "honeypot_port_map"}

    @pytest.mark.asyncio
    async def test_start_survives_ebpf_map_failure(self):
        engine = AsyncPortHoppingEngine(db_session_factory=MagicMock())
        engine._bpf = MagicMock()
        engine._bpf.get_table.side_effect = RuntimeError("no such map")

        await engine.start()  # must not raise — logged and worker still starts
        assert engine._worker_task is not None
        await engine.stop()


class TestAsyncEngineHoppingLoop:
    @pytest.mark.asyncio
    async def test_one_cycle_updates_node_ports_and_syncs_to_nodes(self, monkeypatch):
        node = SimpleNamespace(id=1, protocol=SimpleNamespace(value="vless_reality"), is_active=True)
        node_db = SimpleNamespace(id=1, port=443)

        session = AsyncMock()
        session.execute.return_value = MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[node]))))
        session.get.return_value = node_db

        engine = AsyncPortHoppingEngine(db_session_factory=_session_factory_with(session))

        sync_mock = AsyncMock()
        monkeypatch.setattr(
            "backend.app.orchestrator.orchestrator.sync_node_config", sync_mock
        )

        async def _one_shot_sleep(_seconds):
            engine._is_running = False

        monkeypatch.setattr("backend.app.generators.port_hopper.asyncio.sleep", _one_shot_sleep)

        engine._is_running = True
        await engine._hopping_loop()

        # The node's DB row was repointed at the freshly hopped port...
        assert node_db.port == engine.hopper._current_port
        # ...and the change was pushed to the node daemon.
        sync_mock.assert_awaited_once()
        payload = sync_mock.await_args.args[1]["payload"]
        assert payload["action"] == "update_port"
        assert payload["new_port"] == engine.hopper._current_port

    @pytest.mark.asyncio
    async def test_one_cycle_pushes_new_port_into_ebpf_map(self, monkeypatch):
        node = SimpleNamespace(id=1, protocol=SimpleNamespace(value="vless_reality"), is_active=True)
        session = AsyncMock()
        session.execute.return_value = MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[node]))))
        session.get.return_value = SimpleNamespace(id=1, port=443)

        engine = AsyncPortHoppingEngine(db_session_factory=_session_factory_with(session))
        fake_map = MagicMock()
        fake_map.Key = MagicMock(return_value="k")
        fake_map.Leaf = MagicMock(return_value="v")
        engine._bpf = MagicMock()
        engine._bpf.get_table.return_value = fake_map

        monkeypatch.setattr("backend.app.orchestrator.orchestrator.sync_node_config", AsyncMock())

        async def _one_shot_sleep(_seconds):
            engine._is_running = False

        monkeypatch.setattr("backend.app.generators.port_hopper.asyncio.sleep", _one_shot_sleep)

        engine._is_running = True
        await engine._hopping_loop()

        fake_map.Leaf.assert_called_with(engine.hopper._current_port)

    @pytest.mark.asyncio
    async def test_loop_exits_cleanly_on_cancellation(self, monkeypatch):
        engine = AsyncPortHoppingEngine(db_session_factory=MagicMock())

        async def _cancel(_seconds):
            raise asyncio.CancelledError()

        monkeypatch.setattr("backend.app.generators.port_hopper.asyncio.sleep", _cancel)

        engine._is_running = True
        await engine._hopping_loop()  # must return, not propagate

    @pytest.mark.asyncio
    async def test_loop_survives_db_errors_and_backs_off(self, monkeypatch):
        class _BoomFactory:
            def __call__(self):
                raise RuntimeError("db gone")

        engine = AsyncPortHoppingEngine(db_session_factory=_BoomFactory())
        monkeypatch.setattr("backend.app.orchestrator.orchestrator.sync_node_config", AsyncMock())

        sleeps: list[float] = []

        async def _tracking_sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) >= 2:  # first the 6h hop wait, then the 60s error backoff
                engine._is_running = False

        monkeypatch.setattr("backend.app.generators.port_hopper.asyncio.sleep", _tracking_sleep)

        engine._is_running = True
        await engine._hopping_loop()  # must not raise

        assert 60 in sleeps  # the error-path backoff ran

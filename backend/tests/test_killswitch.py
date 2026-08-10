"""
MTGroup VPN Ultimate — Kill Switch Test Suite
Tests backend/app/core/killswitch.py's lockdown/release logic against the
privileged helper client (mocked — no real iptables/route calls, no real
Unix socket needed).
"""

from __future__ import annotations

import asyncio

import pytest

from backend.app.core.killswitch import EBPFKillSwitch
from backend.app.core.privileged_helper import HelperResponse, PrivilegedHelperError


@pytest.fixture
def switch():
    return EBPFKillSwitch()


class TestTriggerLockdown:
    @pytest.mark.asyncio
    async def test_calls_helper_with_whitelisted_ports(self, switch, monkeypatch):
        calls = []

        async def _fake_helper_request(operation, payload=None, **kw):
            calls.append((operation, payload))
            return HelperResponse(ok=True, message="killswitch applied")

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request", _fake_helper_request,
        )
        # The watchdog thread trigger_lockdown() spawns uses the *sync*
        # client for its periodic status check — patch it too so that
        # background thread never opens a real (or on this platform,
        # nonexistent) AF_UNIX socket.
        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request_sync",
            lambda *a, **kw: HelperResponse(ok=True, data={"linked": True}),
        )

        await switch.trigger_lockdown()
        try:
            assert switch.active is True
            assert ("killswitch.apply", {"whitelist_ports": switch.whitelisted_tcp_ports}) in calls
        finally:
            switch._stop_monitor.set()  # stop the watchdog thread the trigger spawned
            if switch._monitor_thread:
                switch._monitor_thread.join(timeout=2)

    @pytest.mark.asyncio
    async def test_is_idempotent_when_already_active(self, switch, monkeypatch):
        call_count = 0

        async def _fake_helper_request(operation, payload=None, **kw):
            nonlocal call_count
            call_count += 1
            return HelperResponse(ok=True)

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request", _fake_helper_request,
        )
        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request_sync",
            lambda *a, **kw: HelperResponse(ok=True, data={"linked": True}),
        )

        try:
            await switch.trigger_lockdown()
            first_count = call_count
            await switch.trigger_lockdown()  # already active — must be a no-op
            assert call_count == first_count
        finally:
            switch._stop_monitor.set()
            if switch._monitor_thread:
                switch._monitor_thread.join(timeout=2)

    @pytest.mark.asyncio
    async def test_helper_unreachable_does_not_raise(self, switch, monkeypatch):
        async def _fake_helper_request(operation, payload=None, **kw):
            raise PrivilegedHelperError("no socket")

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request", _fake_helper_request,
        )
        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request_sync",
            lambda *a, **kw: HelperResponse(ok=True, data={"linked": True}),
        )

        await switch.trigger_lockdown()  # must not raise even if the helper is down
        try:
            assert switch.active is True  # state still flips — Layer 1/eBPF may still work
        finally:
            switch._stop_monitor.set()
            if switch._monitor_thread:
                switch._monitor_thread.join(timeout=2)

    @pytest.mark.asyncio
    async def test_ebpf_layer_used_when_bpf_module_present(self, switch, monkeypatch):
        async def _fake_helper_request(operation, payload=None, **kw):
            return HelperResponse(ok=True)

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request", _fake_helper_request,
        )
        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request_sync",
            lambda *a, **kw: HelperResponse(ok=True, data={"linked": True}),
        )

        table = {}

        class _FakeMap(dict):
            def Key(self, v):
                return v

            def Leaf(self, v):
                return v

        class _FakeBPF:
            def get_table(self, name):
                return table.setdefault(name, _FakeMap())

        switch.initialize(_FakeBPF())
        try:
            await switch.trigger_lockdown()
            assert table["active_killswitch_map"][0] == 1
        finally:
            switch._stop_monitor.set()
            if switch._monitor_thread:
                switch._monitor_thread.join(timeout=2)


class TestReleaseLockdown:
    @pytest.mark.asyncio
    async def test_noop_when_not_active(self, switch, monkeypatch):
        called = False

        async def _fake_helper_request(operation, payload=None, **kw):
            nonlocal called
            called = True
            return HelperResponse(ok=True)

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request", _fake_helper_request,
        )
        await switch.release_lockdown()
        assert called is False

    @pytest.mark.asyncio
    async def test_stops_watchdog_and_calls_helper_release(self, switch, monkeypatch):
        calls = []

        async def _fake_helper_request(operation, payload=None, **kw):
            calls.append(operation)
            return HelperResponse(ok=True)

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request", _fake_helper_request,
        )
        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request_sync",
            lambda *a, **kw: HelperResponse(ok=True, data={"linked": True}),
        )

        await switch.trigger_lockdown()
        thread = switch._monitor_thread
        assert thread is not None and thread.is_alive()

        await switch.release_lockdown()
        assert switch.active is False
        assert "killswitch.release" in calls
        # The watchdog thread must actually have stopped, not just been
        # asked to (join(timeout=2) inside release_lockdown should have
        # already waited for it).
        assert not thread.is_alive()

    @pytest.mark.asyncio
    async def test_release_does_not_wait_out_the_watchdog_sleep(self, switch, monkeypatch):
        """
        Releasing must interrupt the watchdog immediately, not race it.

        The loop used to end each iteration with an uninterruptible
        `time.sleep(2)` while `release_lockdown` joined with `timeout=2`.
        A thread that had just entered the sleep therefore ignored the stop
        flag for almost exactly as long as the join was willing to wait —
        so under load, release returned with the watchdog still alive and
        still holding its "should be active" view, free to re-apply the
        lockdown *after* it had been released. It also made this test file
        flake in a loaded full-suite run while passing in isolation.
        """
        import time as _time

        async def _fake_helper_request(operation, payload=None, **kw):
            return HelperResponse(ok=True)

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request", _fake_helper_request,
        )
        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request_sync",
            lambda *a, **kw: HelperResponse(ok=True, data={"linked": True}),
        )

        await switch.trigger_lockdown()
        thread = switch._monitor_thread
        await asyncio.sleep(0.2)  # let the watchdog reach its wait

        started = _time.monotonic()
        await switch.release_lockdown()
        elapsed = _time.monotonic() - started

        assert not thread.is_alive()
        # Generous bound: the point is that it returns promptly rather than
        # burning the full 2s interval, without being sensitive to load.
        assert elapsed < 1.0, f"release_lockdown waited {elapsed:.2f}s for the watchdog"


class TestWatchdogLoop:
    def test_reapplies_when_helper_reports_unlinked(self, switch, monkeypatch):
        """Regression check for the watchdog's self-healing behaviour:
        if `killswitch.status` reports the iptables chain got unlinked
        while the switch should still be active, it must re-apply — this
        is the whole point of the watchdog thread. Runs the REAL
        `_watchdog_loop` (not a re-implementation of its logic) directly
        on the test thread, for a couple of iterations, with `time.sleep`
        patched to something fast."""
        status_calls = []
        apply_calls = []
        iterations = 0

        def _fake_helper_request_sync(operation, payload=None, **kw):
            nonlocal iterations
            if operation == "killswitch.status":
                status_calls.append(1)
                iterations += 1
                if iterations >= 2:
                    switch._stop_monitor.set()  # let the loop exit after 2 checks
                return HelperResponse(ok=True, data={"linked": False})
            if operation == "killswitch.apply":
                apply_calls.append(1)
                return HelperResponse(ok=True)
            return HelperResponse(ok=True)

        monkeypatch.setattr(
            "backend.app.core.killswitch.helper_request_sync", _fake_helper_request_sync,
        )
        # Keep the loop fast. The inter-iteration pause is now
        # `self._stop_monitor.wait(2)` rather than an uninterruptible
        # `time.sleep(2)` (see test_release_does_not_wait_out_the_watchdog_sleep),
        # so shortening it means stubbing the event's wait, not time.sleep.
        monkeypatch.setattr(switch._stop_monitor, "wait", lambda timeout=None: False)

        switch.active = True
        switch._stop_monitor.clear()
        switch._watchdog_loop()  # runs on this thread, exits once _stop_monitor is set

        assert len(status_calls) == 2
        assert len(apply_calls) == 2

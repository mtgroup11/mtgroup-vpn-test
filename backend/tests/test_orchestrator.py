"""
MTGroup VPN Ultimate — Node Orchestrator Test Suite
Tests backend/app/orchestrator.py's HMAC signing, node sync/health-check
(with the httpx client and DB session mocked — no real node/network), the
retry queue's backoff logic, and IP ban enforcement.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from backend.app.orchestrator import NodeOrchestrator, RetryTask


def _make_node(**overrides):
    defaults = dict(id=1, name="node-1", address="10.0.0.5", port=8443, api_key="test-api-key")
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _db_factory_with_session(session: AsyncMock):
    class _Ctx:
        async def __aenter__(self):
            return session

        async def __aexit__(self, *exc):
            return False

    return lambda: _Ctx()


@pytest.fixture
def orch():
    o = NodeOrchestrator()
    yield o


class TestGenerateSignature:
    def test_is_deterministic_hmac_sha256(self, orch):
        sig1 = orch._generate_signature("key", b"body")
        sig2 = orch._generate_signature("key", b"body")
        assert sig1 == sig2
        expected = hmac.new(b"key", b"body", hashlib.sha256).hexdigest()
        assert sig1 == expected

    def test_different_keys_produce_different_signatures(self, orch):
        assert orch._generate_signature("key1", b"body") != orch._generate_signature("key2", b"body")


class TestSendRequest:
    @pytest.mark.asyncio
    async def test_post_includes_signature_and_timestamp_headers(self, orch, monkeypatch):
        captured = {}

        async def _fake_post(url, content=None, headers=None):
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            return httpx.Response(200, request=httpx.Request("POST", url))

        monkeypatch.setattr(orch._client, "post", _fake_post)

        await orch._send_request("10.0.0.5", 8443, "secret-key", "POST", "/api/v1/sync", {"foo": "bar"})

        assert captured["url"] == "https://10.0.0.5:8443/api/v1/sync"
        assert "X-MTGroup-Signature" in captured["headers"]
        assert "X-MTGroup-Timestamp" in captured["headers"]
        body = json.loads(captured["content"])
        assert body["foo"] == "bar"
        assert "_ts" in body

    @pytest.mark.asyncio
    async def test_get_does_not_send_a_body(self, orch, monkeypatch):
        captured = {}

        async def _fake_get(url, headers=None):
            captured["headers"] = headers
            return httpx.Response(200, request=httpx.Request("GET", url))

        monkeypatch.setattr(orch._client, "get", _fake_get)

        await orch._send_request("10.0.0.5", 8443, "secret-key", "GET", "/api/v1/health")
        assert "X-MTGroup-Signature" in captured["headers"]

    @pytest.mark.asyncio
    async def test_rejects_unsupported_method(self, orch):
        with pytest.raises(ValueError):
            await orch._send_request("10.0.0.5", 8443, "key", "DELETE", "/api/v1/sync")

    @pytest.mark.asyncio
    async def test_payload_is_not_mutated(self, orch, monkeypatch):
        """`_send_request` must not add `_ts` to the caller's own dict —
        it should copy first."""
        async def _fake_post(url, content=None, headers=None):
            return httpx.Response(200, request=httpx.Request("POST", url))

        monkeypatch.setattr(orch._client, "post", _fake_post)

        original_payload = {"foo": "bar"}
        await orch._send_request("10.0.0.5", 8443, "key", "POST", "/api/v1/sync", original_payload)
        assert original_payload == {"foo": "bar"}


class TestSyncNodeConfig:
    @pytest.mark.asyncio
    async def test_success_does_not_queue_retry(self, orch, monkeypatch):
        async def _fake_send(*a, **kw):
            return httpx.Response(200, request=httpx.Request("POST", "https://x"))

        monkeypatch.setattr(orch, "_send_request", _fake_send)

        await orch.sync_node_config(_make_node(), {"config_type": "test"})
        assert orch._retry_queue.empty()

    @pytest.mark.asyncio
    async def test_failure_queues_a_retry_task(self, orch, monkeypatch):
        async def _fake_send(*a, **kw):
            raise httpx.ConnectError("unreachable")

        monkeypatch.setattr(orch, "_send_request", _fake_send)
        monkeypatch.setattr(orch, "_mark_node_offline", AsyncMock())

        node = _make_node()
        await orch.sync_node_config(node, {"config_type": "test"})

        assert orch._retry_queue.qsize() == 1
        task: RetryTask = await orch._retry_queue.get()
        assert task.node_id == node.id
        assert task.attempt == 1
        orch._mark_node_offline.assert_awaited_once_with(node.id)

    @pytest.mark.asyncio
    async def test_http_error_status_also_queues_retry(self, orch, monkeypatch):
        async def _fake_send(*a, **kw):
            resp = httpx.Response(500, request=httpx.Request("POST", "https://x"))
            resp.raise_for_status()  # raises HTTPStatusError

        monkeypatch.setattr(orch, "_send_request", _fake_send)
        monkeypatch.setattr(orch, "_mark_node_offline", AsyncMock())

        await orch.sync_node_config(_make_node(), {})
        assert orch._retry_queue.qsize() == 1


class TestCheckNodeHealth:
    @pytest.mark.asyncio
    async def test_updates_db_on_success(self, orch, monkeypatch):
        db_node = SimpleNamespace(id=1, is_active=False, health_status="offline", current_connections=0, last_health_check=None)
        session = AsyncMock()
        session.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=db_node))
        orch._db_session_factory = _db_factory_with_session(session)

        async def _fake_send(*a, **kw):
            return httpx.Response(
                200, request=httpx.Request("GET", "https://x"),
                json={"status": "healthy", "current_connections": 42},
            )

        monkeypatch.setattr(orch, "_send_request", _fake_send)

        await orch.check_node_health(_make_node())

        assert db_node.is_active is True
        assert db_node.health_status == "healthy"
        assert db_node.current_connections == 42
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_marks_offline_on_failure(self, orch, monkeypatch):
        async def _fake_send(*a, **kw):
            raise httpx.ConnectError("down")

        monkeypatch.setattr(orch, "_send_request", _fake_send)
        monkeypatch.setattr(orch, "_mark_node_offline", AsyncMock())

        node = _make_node()
        await orch.check_node_health(node)
        orch._mark_node_offline.assert_awaited_once_with(node.id)


class TestIpBanEnforcement:
    @pytest.mark.asyncio
    async def test_apply_and_lift_use_app_level_set_when_ebpf_disabled(self, orch, monkeypatch):
        from backend.app.core.config import settings

        monkeypatch.setattr(settings, "EBPF_ENABLED", False)

        await orch.apply_ip_ban("203.0.113.1")
        assert orch.is_app_banned("203.0.113.1") is True

        await orch.lift_ip_ban("203.0.113.1")
        assert orch.is_app_banned("203.0.113.1") is False

    @pytest.mark.asyncio
    async def test_apply_and_lift_use_xdp_loader_when_ebpf_enabled(self, orch, monkeypatch):
        from backend.app.core.config import settings
        from backend.app.api.metrics import xdp_loader

        monkeypatch.setattr(settings, "EBPF_ENABLED", True)
        monkeypatch.setattr(xdp_loader, "blacklist_ip", MagicMock())
        monkeypatch.setattr(xdp_loader, "unblacklist_ip", MagicMock())

        await orch.apply_ip_ban("203.0.113.2")
        xdp_loader.blacklist_ip.assert_called_once_with("203.0.113.2")
        # App-level set must NOT be used in this mode.
        assert orch.is_app_banned("203.0.113.2") is False

        await orch.lift_ip_ban("203.0.113.2")
        xdp_loader.unblacklist_ip.assert_called_once_with("203.0.113.2")

    @pytest.mark.asyncio
    async def test_handle_security_alert_bans_and_persists(self, orch, monkeypatch):
        from backend.app.core.config import settings

        monkeypatch.setattr(settings, "EBPF_ENABLED", False)
        session = AsyncMock()
        session.add = MagicMock()  # real SQLAlchemy Session.add() is sync
        orch._db_session_factory = _db_factory_with_session(session)
        monkeypatch.setattr(orch, "_remove_ban_after_ttl", AsyncMock())

        await orch.handle_security_alert("203.0.113.3", "anomalous traffic spike")

        assert orch.is_app_banned("203.0.113.3") is True
        session.add.assert_called_once()
        session.commit.assert_awaited_once()
        banned_row = session.add.call_args.args[0]
        assert banned_row.ip_address == "203.0.113.3"
        assert banned_row.details == "anomalous traffic spike"

    @pytest.mark.asyncio
    async def test_handle_security_alert_does_not_raise_on_db_failure(self, orch, monkeypatch):
        from backend.app.core.config import settings

        monkeypatch.setattr(settings, "EBPF_ENABLED", False)
        session = AsyncMock()
        session.add = MagicMock()
        session.commit.side_effect = RuntimeError("db down")
        orch._db_session_factory = _db_factory_with_session(session)

        await orch.handle_security_alert("203.0.113.4", "test")  # must not raise

    @pytest.mark.asyncio
    async def test_remove_ban_after_ttl_lifts_ban(self, orch, monkeypatch):
        from backend.app.core.config import settings

        monkeypatch.setattr(settings, "EBPF_ENABLED", False)

        async def _fast_sleep(_seconds):
            return None

        monkeypatch.setattr("backend.app.orchestrator.asyncio.sleep", _fast_sleep)

        orch._app_banned_ips.add("203.0.113.5")
        await orch._remove_ban_after_ttl("203.0.113.5", ttl=300)
        assert orch.is_app_banned("203.0.113.5") is False


class TestBroadcastMeshPeers:
    @pytest.mark.asyncio
    async def test_noop_with_fewer_than_two_active_nodes(self, orch, monkeypatch):
        session = AsyncMock()
        session.execute.return_value = MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[_make_node()]))))
        orch._db_session_factory = _db_factory_with_session(session)

        send_spy = AsyncMock()
        monkeypatch.setattr(orch, "_send_request", send_spy)

        await orch.broadcast_mesh_peers()
        send_spy.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcasts_peer_list_excluding_self(self, orch, monkeypatch):
        node_a = _make_node(id=1, name="a", address="10.0.0.1")
        node_b = _make_node(id=2, name="b", address="10.0.0.2")
        session = AsyncMock()
        session.execute.return_value = MagicMock(
            scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[node_a, node_b])))
        )
        orch._db_session_factory = _db_factory_with_session(session)

        sent_payloads = []

        async def _fake_send(*, address, port, api_key, method, endpoint, payload):
            sent_payloads.append((address, payload))
            return httpx.Response(200, request=httpx.Request("POST", "https://x"))

        monkeypatch.setattr(orch, "_send_request", _fake_send)

        await orch.broadcast_mesh_peers()
        # broadcast fires fire-and-forget asyncio.create_task() calls —
        # give the event loop a tick to actually run them.
        import asyncio
        await asyncio.sleep(0)

        addresses = {addr for addr, _ in sent_payloads}
        assert addresses == {node_a.address, node_b.address}

        id_by_address = {node_a.address: node_a.id, node_b.address: node_b.id}
        for address, payload in sent_payloads:
            this_node_id = id_by_address[address]
            peer_ids = [p["id"] for p in payload["peers"]]
            other_node_id = node_b.id if this_node_id == node_a.id else node_a.id
            assert peer_ids == [other_node_id]
            # A node must never receive itself as a peer.
            assert this_node_id not in peer_ids


class TestBackgroundWorkerLoopBackoff:
    @pytest.mark.asyncio
    async def test_failed_retry_reschedules_with_exponential_backoff(self, orch, monkeypatch):
        """Runs the REAL `_background_worker_loop` (not a re-implementation
        of its logic) as a task, with `_send_request` always failing and
        `asyncio.sleep` faked out so the test doesn't wait on real time.
        The loop is stopped after the retry has been requeued once."""
        async def _fake_send(*a, **kw):
            raise httpx.ConnectError("still down")

        monkeypatch.setattr(orch, "_send_request", _fake_send)

        real_sleep = __import__("asyncio").sleep
        sleep_calls = 0

        async def _fake_sleep(seconds):
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls >= 4:
                orch._is_running = False
            await real_sleep(0)  # yield control without a real delay

        monkeypatch.setattr("backend.app.orchestrator.asyncio.sleep", _fake_sleep)

        task = RetryTask(
            node_id=1, node_address="10.0.0.5", node_port=8443, api_key="k",
            endpoint="/api/v1/sync", method="POST", payload={}, attempt=1, next_retry_at=0.0,
        )
        await orch._retry_queue.put(task)

        orch._is_running = True
        import asyncio as _asyncio
        await _asyncio.wait_for(orch._background_worker_loop(), timeout=5.0)

        assert orch._retry_queue.qsize() == 1
        requeued = orch._retry_queue.get_nowait()
        assert requeued.attempt == 2
        assert requeued.next_retry_at > time.time()  # real backoff scheduling, not immediate


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop_is_clean(self, orch):
        await orch.start()
        assert orch._is_running is True
        await orch.stop()
        assert orch._is_running is False
        assert orch._client.is_closed

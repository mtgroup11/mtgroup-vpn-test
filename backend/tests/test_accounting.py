"""
MTGroup VPN Ultimate — Traffic Accounting Engine Test Suite
Covers `ingest_traffic`'s buffering logic (pure, no DB needed), plus
`_process_accounting`'s bulk-update/quota-suspension path and
`_drop_user_from_nodes` against a real (SQLite, fixture-backed) DB session,
and the start/stop lifecycle of the background loop.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from backend.app.core.accounting import TrafficAccountingEngine
from backend.app.core.security import hash_password
from backend.app.models import Agent, Node, NodeProtocol, User


@pytest.fixture
def engine():
    return TrafficAccountingEngine(db_session_factory=lambda: None)


class TestIngestTraffic:
    @pytest.mark.asyncio
    async def test_accumulates_across_multiple_calls(self, engine):
        await engine.ingest_traffic(user_id=1, bytes_delta=100)
        await engine.ingest_traffic(user_id=1, bytes_delta=250)
        assert engine._traffic_buffer[1] == 350

    @pytest.mark.asyncio
    async def test_tracks_separate_users_independently(self, engine):
        await engine.ingest_traffic(user_id=1, bytes_delta=100)
        await engine.ingest_traffic(user_id=2, bytes_delta=200)
        assert engine._traffic_buffer == {1: 100, 2: 200}

    @pytest.mark.asyncio
    async def test_ignores_zero_or_negative_delta(self, engine):
        await engine.ingest_traffic(user_id=1, bytes_delta=0)
        await engine.ingest_traffic(user_id=1, bytes_delta=-50)
        assert 1 not in engine._traffic_buffer


class TestStartStop:
    @pytest.mark.asyncio
    async def test_start_spawns_worker_task_and_is_idempotent(self, engine):
        await engine.start()
        assert engine._is_running is True
        task = engine._worker_task
        assert task is not None and not task.done()

        # Calling start() again while already running must not spawn a
        # second worker task (the early-return guard at the top of start()).
        await engine.start()
        assert engine._worker_task is task

        await engine.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_worker_task(self, engine):
        await engine.start()
        task = engine._worker_task
        await engine.stop()
        assert engine._is_running is False
        assert task.done()

    @pytest.mark.asyncio
    async def test_stop_without_start_is_a_noop(self, engine):
        await engine.stop()
        assert engine._is_running is False


@pytest_asyncio.fixture
async def acct_engine(db_engine):
    from backend.app.models import create_session_factory

    factory = create_session_factory(db_engine)
    return TrafficAccountingEngine(db_session_factory=factory), factory


class TestProcessAccounting:
    @pytest.mark.asyncio
    async def test_empty_buffer_is_a_noop(self, acct_engine):
        engine, _factory = acct_engine
        # No session_factory call should happen — buffer is empty.
        await engine._process_accounting()

    @pytest.mark.asyncio
    async def test_bulk_updates_usage_bytes_for_buffered_users(self, acct_engine, monkeypatch):
        engine, factory = acct_engine
        monkeypatch.setattr(
            "backend.app.core.accounting.orchestrator.sync_node_config", AsyncMock()
        )

        async with factory() as session:
            user = User(
                username="acct-user-1",
                hashed_password=hash_password("Pw123456!"),
                data_used_bytes=1000,
                current_period_usage_bytes=1000,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            user_id = user.id

        await engine.ingest_traffic(user_id=user_id, bytes_delta=500)
        await engine._process_accounting()

        async with factory() as session:
            refreshed = await session.get(User, user_id)
            assert refreshed.data_used_bytes == 1500
            assert refreshed.current_period_usage_bytes == 1500
            assert refreshed.is_active is True

        # Buffer should have been swapped out and consumed.
        assert engine._traffic_buffer == {}

    @pytest.mark.asyncio
    async def test_suspends_user_over_lifetime_data_limit(self, acct_engine, monkeypatch):
        engine, factory = acct_engine
        sync_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.accounting.orchestrator.sync_node_config", sync_mock)

        async with factory() as session:
            node = Node(name="acct-node-1", address="10.0.0.9", protocol=NodeProtocol.VLESS_REALITY)
            user = User(
                username="acct-over-limit",
                hashed_password=hash_password("Pw123456!"),
                data_limit_bytes=1000,
                data_used_bytes=900,
                is_active=True,
            )
            session.add_all([node, user])
            await session.commit()
            await session.refresh(user)
            user_id = user.id

        # _drop_user_from_nodes is fired via a detached asyncio.create_task,
        # so wait for whatever new task _process_accounting spawns rather
        # than a fixed number of event-loop ticks (which flaked under load).
        import asyncio
        tasks_before = asyncio.all_tasks()
        await engine.ingest_traffic(user_id=user_id, bytes_delta=200)  # 900 + 200 >= 1000
        await engine._process_accounting()
        spawned = asyncio.all_tasks() - tasks_before - {asyncio.current_task()}
        if spawned:
            await asyncio.gather(*spawned)

        async with factory() as session:
            refreshed = await session.get(User, user_id)
            assert refreshed.is_active is False

        sync_mock.assert_awaited()

    @pytest.mark.asyncio
    async def test_suspends_user_over_periodic_data_limit(self, acct_engine, monkeypatch):
        engine, factory = acct_engine
        monkeypatch.setattr(
            "backend.app.core.accounting.orchestrator.sync_node_config", AsyncMock()
        )

        async with factory() as session:
            user = User(
                username="acct-periodic-limit",
                hashed_password=hash_password("Pw123456!"),
                periodic_data_limit_bytes=1000,
                current_period_usage_bytes=950,
                is_active=True,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            user_id = user.id

        await engine.ingest_traffic(user_id=user_id, bytes_delta=100)  # 950 + 100 >= 1000
        await engine._process_accounting()

        async with factory() as session:
            refreshed = await session.get(User, user_id)
            assert refreshed.is_active is False

    @pytest.mark.asyncio
    async def test_users_under_quota_stay_active(self, acct_engine, monkeypatch):
        engine, factory = acct_engine
        monkeypatch.setattr(
            "backend.app.core.accounting.orchestrator.sync_node_config", AsyncMock()
        )

        async with factory() as session:
            user = User(
                username="acct-under-limit",
                hashed_password=hash_password("Pw123456!"),
                data_limit_bytes=10_000,
                data_used_bytes=100,
                is_active=True,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            user_id = user.id

        await engine.ingest_traffic(user_id=user_id, bytes_delta=50)
        await engine._process_accounting()

        async with factory() as session:
            refreshed = await session.get(User, user_id)
            assert refreshed.is_active is True

    @pytest.mark.asyncio
    async def test_suspends_agent_and_cascades_to_sub_users(self, acct_engine, monkeypatch):
        engine, factory = acct_engine
        monkeypatch.setattr(
            "backend.app.core.accounting.orchestrator.sync_node_config", AsyncMock()
        )

        async with factory() as session:
            owner = User(
                username="acct-agent-owner",
                hashed_password=hash_password("Pw123456!"),
            )
            session.add(owner)
            await session.commit()
            await session.refresh(owner)

            agent = Agent(
                user_id=owner.id,
                traffic_quota_bytes=1000,
                traffic_used_bytes=1200,  # already over quota
                is_active=True,
            )
            session.add(agent)
            await session.commit()
            await session.refresh(agent)

            sub_user = User(
                username="acct-agent-subuser",
                hashed_password=hash_password("Pw123456!"),
                agent_id=agent.id,
                is_active=True,
            )
            session.add(sub_user)
            await session.commit()
            await session.refresh(sub_user)
            sub_user_id = sub_user.id
            agent_id = agent.id

        # Buffer needs at least one entry for _process_accounting to run
        # past its early-return; the agent-quota check is independent of
        # which user triggered the cycle.
        await engine.ingest_traffic(user_id=sub_user_id, bytes_delta=1)
        await engine._process_accounting()

        async with factory() as session:
            refreshed_agent = await session.get(Agent, agent_id)
            refreshed_sub_user = await session.get(User, sub_user_id)
            assert refreshed_agent.is_active is False
            assert refreshed_sub_user.is_active is False

    @pytest.mark.asyncio
    async def test_db_failure_pushes_buffer_back_for_retry(self, acct_engine):
        engine, _factory = acct_engine

        class _BoomFactory:
            def __call__(self):
                raise RuntimeError("db unavailable")

        engine._db_session_factory = _BoomFactory()
        await engine.ingest_traffic(user_id=42, bytes_delta=777)
        await engine._process_accounting()

        assert engine._traffic_buffer == {42: 777}

    @pytest.mark.asyncio
    async def test_retry_buffer_is_bounded_during_a_sustained_db_outage(self, acct_engine, monkeypatch):
        # Without a cap, every failed cycle re-adds its deltas and the dict
        # grows for as long as the outage lasts — in a worker designed to run
        # forever. Verify the bound actually holds rather than just trusting
        # the constant exists.
        engine, _factory = acct_engine
        monkeypatch.setattr(type(engine), "MAX_BUFFER_ENTRIES", 100)

        class _BoomFactory:
            def __call__(self):
                raise RuntimeError("db unavailable")

        engine._db_session_factory = _BoomFactory()

        for user_id in range(500):
            await engine.ingest_traffic(user_id=user_id, bytes_delta=10)
        await engine._process_accounting()

        assert len(engine._traffic_buffer) == 100
        # Oldest dropped, most recent traffic kept.
        assert 499 in engine._traffic_buffer
        assert 0 not in engine._traffic_buffer

    @pytest.mark.asyncio
    async def test_retry_buffer_under_the_cap_is_untouched(self, acct_engine, monkeypatch):
        engine, _factory = acct_engine
        monkeypatch.setattr(type(engine), "MAX_BUFFER_ENTRIES", 100)

        class _BoomFactory:
            def __call__(self):
                raise RuntimeError("db unavailable")

        engine._db_session_factory = _BoomFactory()

        for user_id in range(10):
            await engine.ingest_traffic(user_id=user_id, bytes_delta=10)
        await engine._process_accounting()

        assert len(engine._traffic_buffer) == 10
        assert engine._traffic_buffer[0] == 10  # nothing evicted, nothing lost


class TestDropUserFromNodes:
    @pytest.mark.asyncio
    async def test_syncs_drop_payload_to_all_active_nodes(self, acct_engine, monkeypatch):
        engine, factory = acct_engine
        sync_mock = AsyncMock()
        monkeypatch.setattr("backend.app.core.accounting.orchestrator.sync_node_config", sync_mock)

        async with factory() as session:
            active_node = Node(name="drop-node-active", address="10.0.0.10", protocol=NodeProtocol.VLESS_REALITY, is_active=True)
            inactive_node = Node(name="drop-node-inactive", address="10.0.0.11", protocol=NodeProtocol.VLESS_REALITY, is_active=False)
            user = User(username="drop-target-user", hashed_password=hash_password("Pw123456!"))
            session.add_all([active_node, inactive_node, user])
            await session.commit()
            await session.refresh(user)

        await engine._drop_user_from_nodes(user)

        sync_mock.assert_awaited_once()
        call_args = sync_mock.await_args
        assert call_args.args[0].name == "drop-node-active"
        assert call_args.args[1]["payload"]["action"] == "drop_user"
        assert call_args.args[1]["payload"]["user_uuid"] == "drop-target-user"

    @pytest.mark.asyncio
    async def test_swallows_orchestrator_errors(self, acct_engine, monkeypatch):
        engine, factory = acct_engine
        monkeypatch.setattr(
            "backend.app.core.accounting.orchestrator.sync_node_config",
            AsyncMock(side_effect=RuntimeError("node unreachable")),
        )

        async with factory() as session:
            node = Node(name="drop-node-erroring", address="10.0.0.12", protocol=NodeProtocol.VLESS_REALITY)
            user = User(username="drop-erroring-user", hashed_password=hash_password("Pw123456!"))
            session.add_all([node, user])
            await session.commit()
            await session.refresh(user)

        # Should not raise — errors are logged and swallowed.
        await engine._drop_user_from_nodes(user)


class TestConsumeDelta:
    """Pure logic, no DB — the cumulative-counter-to-delta conversion that
    every node-traffic path (AmneziaWG, Xray) relies on."""

    def test_first_observation_is_the_full_value(self, engine):
        assert engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=500) == 500

    def test_second_observation_is_the_difference(self, engine):
        engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=500)
        assert engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=800) == 300

    def test_counter_reset_returns_the_new_value_not_a_negative_delta(self, engine):
        """
        A node/service restart resets the cumulative counter to (near)
        zero. `new - old` would be negative here and get silently dropped
        by ingest_traffic() — the correct delta is the new value itself
        (traffic accrued since the reset).
        """
        engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=10_000)
        assert engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=50) == 50

    def test_different_identifiers_on_the_same_node_are_independent(self, engine):
        engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=100)
        engine._consume_delta(node_id=1, identifier="b", cumulative_bytes=999)
        assert engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=150) == 50

    def test_same_identifier_on_different_nodes_is_independent(self, engine):
        engine._consume_delta(node_id=1, identifier="a", cumulative_bytes=100)
        # A different node reporting the same identifier string starts its
        # own tracking from zero, not from node 1's last-seen value.
        assert engine._consume_delta(node_id=2, identifier="a", cumulative_bytes=100) == 100


@pytest_asyncio.fixture
async def amnezia_traffic_env(db_engine):
    """A real user + subscription + AmneziaWG node + provisioned peer."""
    from backend.app.core.wireguard_peers import get_or_create_peer
    from backend.app.models import NodeProtocol, Subscription, create_session_factory

    factory = create_session_factory(db_engine)
    async with factory() as session:
        user = User(username="awg-traffic-user", hashed_password=hash_password("Pw123456!"))
        session.add(user)
        await session.flush()

        sub = Subscription(user_id=user.id, token="awg-traffic-token")
        node = Node(
            name="awg-traffic-node", address="10.0.0.20", protocol=NodeProtocol.AMNEZIA_WG,
            amnezia_subnet="10.9.0.0/24", amnezia_server_public_key="SERVERPUB=",
        )
        session.add_all([sub, node])
        await session.commit()
        await session.refresh(sub)
        await session.refresh(node)

        peer, _created = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        await session.commit()

        user_id, node_obj, public_key = user.id, node, peer.public_key

    return TrafficAccountingEngine(db_session_factory=factory), factory, user_id, node_obj, public_key


class TestIngestAmneziaTraffic:
    @pytest.mark.asyncio
    async def test_maps_public_key_to_user_and_buffers_delta(self, amnezia_traffic_env):
        engine, _factory, user_id, node, public_key = amnezia_traffic_env

        await engine._ingest_amnezia_traffic(node, {public_key: {"rx_bytes": 100, "tx_bytes": 50}})

        assert engine._traffic_buffer == {user_id: 150}

    @pytest.mark.asyncio
    async def test_second_call_ingests_only_the_delta(self, amnezia_traffic_env):
        engine, _factory, user_id, node, public_key = amnezia_traffic_env

        await engine._ingest_amnezia_traffic(node, {public_key: {"rx_bytes": 100, "tx_bytes": 50}})
        await engine._ingest_amnezia_traffic(node, {public_key: {"rx_bytes": 300, "tx_bytes": 50}})

        assert engine._traffic_buffer[user_id] == 150 + 200  # +200 delta from the second call

    @pytest.mark.asyncio
    async def test_unknown_public_key_is_ignored(self, amnezia_traffic_env):
        engine, _factory, user_id, node, _public_key = amnezia_traffic_env

        await engine._ingest_amnezia_traffic(node, {"NEVER-PROVISIONED=": {"rx_bytes": 1, "tx_bytes": 1}})

        assert engine._traffic_buffer == {}


@pytest_asyncio.fixture
async def xray_traffic_env(db_engine):
    from backend.app.api.subscriptions import _generate_user_uuid
    from backend.app.models import NodeProtocol, create_session_factory

    factory = create_session_factory(db_engine)
    async with factory() as session:
        user = User(username="xray-traffic-user", hashed_password=hash_password("Pw123456!"), is_active=True)
        inactive_user = User(username="xray-inactive-user", hashed_password=hash_password("Pw123456!"), is_active=False)
        node = Node(name="xray-traffic-node", address="10.0.0.21", protocol=NodeProtocol.VLESS_REALITY)
        session.add_all([user, inactive_user, node])
        await session.commit()
        await session.refresh(user)
        await session.refresh(inactive_user)
        await session.refresh(node)
        user_id, inactive_user_id, node_obj = user.id, inactive_user.id, node

    email = _generate_user_uuid(user_id, node_obj.id)
    return TrafficAccountingEngine(db_session_factory=factory), user_id, inactive_user_id, node_obj, email


class TestIngestXrayTraffic:
    @pytest.mark.asyncio
    async def test_maps_email_to_user_via_deterministic_uuid_and_buffers(self, xray_traffic_env):
        engine, user_id, _inactive_id, node, email = xray_traffic_env

        await engine._ingest_xray_traffic(node, {email: 12345})

        assert engine._traffic_buffer == {user_id: 12345}

    @pytest.mark.asyncio
    async def test_inactive_users_are_not_matched(self, xray_traffic_env):
        """
        Only active users are candidates for reverse-mapping — an inactive
        user's uuid5 for this node would never legitimately appear in a
        node's stats (nothing provisions inbound clients for suspended
        users), so excluding them narrows the search space too.
        """
        from backend.app.api.subscriptions import _generate_user_uuid

        engine, _user_id, inactive_user_id, node, _email = xray_traffic_env
        inactive_email = _generate_user_uuid(inactive_user_id, node.id)

        await engine._ingest_xray_traffic(node, {inactive_email: 999})

        assert engine._traffic_buffer == {}

    @pytest.mark.asyncio
    async def test_unrecognized_email_is_ignored(self, xray_traffic_env):
        engine, _user_id, _inactive_id, node, _email = xray_traffic_env

        await engine._ingest_xray_traffic(node, {"not-a-real-uuid": 999})

        assert engine._traffic_buffer == {}


class TestIngestNodeTraffic:
    @pytest.mark.asyncio
    async def test_dispatches_amnezia_traffic(self, amnezia_traffic_env):
        engine, _factory, user_id, node, public_key = amnezia_traffic_env

        await engine.ingest_node_traffic(node, {"amnezia_peer_traffic": {public_key: {"rx_bytes": 10, "tx_bytes": 5}}})

        assert engine._traffic_buffer == {user_id: 15}

    @pytest.mark.asyncio
    async def test_dispatches_xray_traffic(self, xray_traffic_env):
        engine, user_id, _inactive_id, node, email = xray_traffic_env

        await engine.ingest_node_traffic(node, {"xray_user_traffic": {email: 42}})

        assert engine._traffic_buffer == {user_id: 42}

    @pytest.mark.asyncio
    async def test_empty_snapshot_is_a_noop(self, engine):
        await engine.ingest_node_traffic(Node(id=1, name="n"), {})
        assert engine._traffic_buffer == {}

    @pytest.mark.asyncio
    async def test_never_raises_even_if_a_sub_ingest_fails(self, engine, monkeypatch):
        async def _boom(*a, **kw):
            raise RuntimeError("db exploded")

        monkeypatch.setattr(engine, "_ingest_amnezia_traffic", _boom)

        # Must not raise.
        await engine.ingest_node_traffic(
            Node(id=1, name="n"), {"amnezia_peer_traffic": {"PUBKEY=": {"rx_bytes": 1, "tx_bytes": 1}}}
        )

"""
Node health vs. the admin's enable switch, against a real database.

A single failed health check used to set `Node.is_active = False`. The poll
loop only checks active nodes and subscriptions only list active nodes, so
one dropped poll removed a server from every user's subscription for good.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from backend.app.models import Node, NodeProtocol, create_session_factory
from backend.app.orchestrator import OFFLINE_AFTER_FAILURES, NodeOrchestrator


async def _node(factory, **kw) -> Node:
    async with factory() as s:
        # agent_cert_pem set so the orchestrator never tries a real TOFU
        # fetch; _send_request is stubbed below anyway.
        node = Node(name=kw.pop("name", "hn"), address="10.0.0.9", port=443,
                    protocol=NodeProtocol.VLESS_REALITY, agent_cert_pem="PEM", **kw)
        s.add(node)
        await s.commit()
        await s.refresh(node)
        return node


async def _reload(factory, node_id) -> Node:
    async with factory() as s:
        return (await s.execute(select(Node).where(Node.id == node_id))).scalar_one()


def _orch(factory, healthy: bool):
    orch = NodeOrchestrator(db_session_factory=factory)

    async def send(*a, **kw):
        if not healthy:
            raise httpx.ConnectError("blip")
        return httpx.Response(200, request=httpx.Request("GET", "https://x"),
                              json={"status": "healthy", "current_connections": 3})
    orch._send_request = send
    return orch


@pytest.mark.asyncio
async def test_failed_check_never_touches_is_active(db_engine):
    factory = create_session_factory(db_engine)
    node = await _node(factory)
    orch = _orch(factory, healthy=False)
    for _ in range(OFFLINE_AFTER_FAILURES + 2):
        await orch.check_node_health(node)
    assert (await _reload(factory, node.id)).is_active is True
    await orch.stop()


@pytest.mark.asyncio
async def test_never_seen_node_is_unreachable_not_offline(db_engine):
    factory = create_session_factory(db_engine)
    node = await _node(factory)
    orch = _orch(factory, healthy=False)
    for _ in range(OFFLINE_AFTER_FAILURES + 2):
        await orch.check_node_health(node)
    assert (await _reload(factory, node.id)).health_status == "unreachable"
    await orch.stop()


@pytest.mark.asyncio
async def test_previously_healthy_node_goes_degraded_then_offline_then_recovers(db_engine):
    factory = create_session_factory(db_engine)
    node = await _node(factory)

    ok = _orch(factory, healthy=True)
    await ok.check_node_health(node)
    assert (await _reload(factory, node.id)).health_status == "healthy"

    bad = _orch(factory, healthy=False)
    bad._health_failures = ok._health_failures
    statuses = []
    for _ in range(OFFLINE_AFTER_FAILURES):
        await bad.check_node_health(node)
        statuses.append((await _reload(factory, node.id)).health_status)
    assert statuses[:-1] == ["degraded"] * (OFFLINE_AFTER_FAILURES - 1)
    assert statuses[-1] == "offline"

    await ok.check_node_health(node)
    back = await _reload(factory, node.id)
    assert back.health_status == "healthy"
    assert ok._health_failures.get(node.id) is None
    for o in (ok, bad):
        await o.stop()


@pytest.mark.asyncio
async def test_success_does_not_re_enable_an_admin_disabled_node(db_engine):
    factory = create_session_factory(db_engine)
    node = await _node(factory, is_active=False)
    orch = _orch(factory, healthy=True)
    await orch.check_node_health(node)
    assert (await _reload(factory, node.id)).is_active is False
    await orch.stop()


@pytest.mark.asyncio
async def test_subscriptions_skip_offline_but_keep_unreachable_nodes(client, db_engine):
    from backend.tests.conftest import get_admin_token
    factory = create_session_factory(db_engine)
    async with factory() as s:
        seeded = (await s.execute(select(Node).where(Node.name == "test-node"))).scalar_one()
        seeded.health_status = "unreachable"
        s.add(Node(name="down-node", address="10.0.0.77", port=443, protocol=NodeProtocol.VLESS_REALITY,
                   reality_public_key="pk", health_status="offline"))
        await s.commit()

    tok = await get_admin_token(client)
    user = (await client.post("/api/users/", json={"username": "hl-user", "password": "Password123!",
                                                     "protocols": ["vless_reality"]},
                              headers={"Authorization": f"Bearer {tok}"})).json()
    links = (await client.get(f"/sub/{user['subscription_token']}/links")).text
    assert "10.0.0.1" in links        # unreachable: kept
    assert "10.0.0.77" not in links   # offline: skipped

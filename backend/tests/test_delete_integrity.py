"""
Deletion integrity. SQLite runs with foreign keys off, so every
`ondelete="CASCADE"` without an ORM cascade was dead code — and one ORM
cascade pointed the wrong way.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from backend.app.core.security import hash_password
from backend.app.models import (
    AbuseReputation,
    Agent,
    Node,
    NodeProtocol,
    Subscription,
    User,
    UserRole,
    WireGuardPeer,
    create_session_factory,
)
from backend.tests.conftest import get_admin_token


@pytest.mark.asyncio
async def test_deleting_a_sub_agent_does_not_delete_its_parent(db_engine):
    factory = create_session_factory(db_engine)
    async with factory() as s:
        pu = User(username="parent-r", hashed_password="x", role=UserRole.RESELLER)
        cu = User(username="child-r", hashed_password="x", role=UserRole.RESELLER)
        s.add_all([pu, cu])
        await s.flush()
        parent = Agent(user_id=pu.id)
        s.add(parent)
        await s.flush()
        child = Agent(user_id=cu.id, parent_agent_id=parent.id)
        s.add(child)
        await s.commit()
        parent_id, child_id = parent.id, child.id

    async with factory() as s:
        child = await s.get(Agent, child_id)
        await s.delete(child)
        await s.commit()
    async with factory() as s:
        assert (await s.execute(select(Agent.id))).scalars().all() == [parent_id]


@pytest.mark.asyncio
async def test_deleting_a_parent_agent_keeps_sub_agents_as_top_level(db_engine):
    factory = create_session_factory(db_engine)
    async with factory() as s:
        pu = User(username="p2", hashed_password="x", role=UserRole.RESELLER)
        cu = User(username="c2", hashed_password="x", role=UserRole.RESELLER)
        s.add_all([pu, cu])
        await s.flush()
        parent = Agent(user_id=pu.id)
        s.add(parent)
        await s.flush()
        s.add(Agent(user_id=cu.id, parent_agent_id=parent.id))
        await s.commit()
        parent_id = parent.id
    async with factory() as s:
        await s.delete(await s.get(Agent, parent_id))
        await s.commit()
    async with factory() as s:
        remaining = (await s.execute(select(Agent))).scalars().all()
        assert len(remaining) == 1 and remaining[0].parent_agent_id is None


@pytest.mark.asyncio
async def test_deleting_a_reseller_removes_their_agent_profile(client, db_engine):
    factory = create_session_factory(db_engine)
    async with factory() as s:
        r = User(username="gone-reseller", hashed_password=hash_password("Reseller123!"), role=UserRole.RESELLER)
        s.add(r)
        await s.flush()
        s.add(Agent(user_id=r.id, traffic_quota_bytes=10**12))
        s.add(AbuseReputation(user_id=r.id))
        await s.commit()
        rid = r.id
    tok = await get_admin_token(client)
    resp = await client.delete(f"/api/users/{rid}", headers={"Authorization": f"Bearer {tok}"})
    assert resp.status_code == 200
    async with factory() as s:
        assert (await s.execute(select(Agent).where(Agent.user_id == rid))).scalars().all() == []
        assert (await s.execute(select(AbuseReputation).where(AbuseReputation.user_id == rid))).scalars().all() == []


@pytest.mark.asyncio
async def test_deleting_a_node_removes_its_wireguard_peers(client, db_engine):
    factory = create_session_factory(db_engine)
    async with factory() as s:
        node = Node(name="awg-del", address="10.0.0.30", port=51820, protocol=NodeProtocol.AMNEZIA_WG)
        u = User(username="peer-owner", hashed_password="x")
        s.add_all([node, u])
        await s.flush()
        sub = Subscription(user_id=u.id, token="peer-del-tok")
        s.add(sub)
        await s.flush()
        s.add(WireGuardPeer(subscription_id=sub.id, node_id=node.id, private_key="k", public_key="p",
                            assigned_ip="10.8.0.2"))
        await s.commit()
        nid = node.id
    tok = await get_admin_token(client)
    assert (await client.delete(f"/api/nodes/{nid}", headers={"Authorization": f"Bearer {tok}"})).status_code == 200
    async with factory() as s:
        assert (await s.execute(select(WireGuardPeer))).scalars().all() == []


@pytest.mark.asyncio
async def test_deactivating_a_user_revokes_their_wireguard_peers(client, monkeypatch):
    revoke = AsyncMock(return_value=1)
    monkeypatch.setattr("backend.app.api.users.revoke_peers", revoke)
    tok = await get_admin_token(client)
    auth = {"Authorization": f"Bearer {tok}"}
    user = (await client.post("/api/users/", json={"username": "deact", "password": "Password123!"},
                              headers=auth)).json()
    await client.patch(f"/api/users/{user['id']}", json={"data_limit_bytes": 5}, headers=auth)
    revoke.assert_not_awaited()
    await client.patch(f"/api/users/{user['id']}", json={"is_active": False}, headers=auth)
    revoke.assert_awaited_once()

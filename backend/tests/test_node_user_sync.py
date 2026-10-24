"""
Node user provisioning (core/node_user_sync.py).

Before this existed no code path told a node which credentials were valid,
and expiry / quota / deletion never took effect on any node.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from backend.app.core import node_user_sync as nus
from backend.app.core.security import derive_proxy_uuid, hash_password
from backend.app.models import Node, NodeProtocol, Subscription, User, create_session_factory


async def _seed(factory, **user_overrides):
    async with factory() as s:
        node = Node(name="vless-1", address="127.0.0.1", port=443, protocol=NodeProtocol.VLESS_REALITY,
                    reality_private_key="cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA", reality_short_id="ab12",
                    sni="www.microsoft.com", agent_cert_pem="PEM")
        s.add(node)
        users = {
            "ok": dict(),
            "expired": dict(expire_date=datetime.now(timezone.utc) - timedelta(days=1)),
            "over_quota": dict(data_limit_bytes=100, data_used_bytes=100),
            "suspended": dict(is_active=False),
        }
        users.update(user_overrides)
        tokens = {}
        for name, kw in users.items():
            u = User(username=name, hashed_password=hash_password("Password123!"), **kw)
            s.add(u)
            await s.flush()
            s.add(Subscription(user_id=u.id, token=f"tok-{name}"))
            tokens[name] = f"tok-{name}"
        s.add(Subscription(user_id=u.id, token="tok-revoked", is_active=False))
        await s.commit()
        await s.refresh(node)
        return node, tokens


class _RecordingOrchestrator:
    def __init__(self, accept=True):
        self.accept = accept
        self.sent = []

    async def send_command(self, node, payload):
        self.sent.append((node.id, payload))
        return self.accept


def _clients(payload):
    inbound = next(i for i in payload["payload"]["inbounds"] if i["protocol"] == "vless")
    return {c["id"] for c in inbound["settings"]["clients"]}


@pytest.mark.asyncio
async def test_only_users_allowed_to_connect_are_provisioned(db_engine):
    factory = create_session_factory(db_engine)
    node, tokens = await _seed(factory)
    orch = _RecordingOrchestrator()
    await nus.NodeUserSync(factory, orch).sync_once()

    assert len(orch.sent) == 1
    assert _clients(orch.sent[0][1]) == {derive_proxy_uuid(tokens["ok"], node.id)}


@pytest.mark.asyncio
async def test_rendered_config_matches_what_subscriptions_hand_out(db_engine):
    factory = create_session_factory(db_engine)
    node, tokens = await _seed(factory)
    orch = _RecordingOrchestrator()
    await nus.NodeUserSync(factory, orch).sync_once()
    cfg = orch.sent[0][1]["payload"]
    inbound = next(i for i in cfg["inbounds"] if i["protocol"] == "vless")
    reality = inbound["streamSettings"]["realitySettings"]
    assert inbound["port"] == node.port
    assert reality["privateKey"] == node.reality_private_key
    assert "ab12" in reality["shortIds"]
    assert reality["serverNames"] == ["www.microsoft.com"]
    client = inbound["settings"]["clients"][0]
    assert client["email"] == client["id"]  # accounting maps stats back by this
    assert orch.sent[0][1]["config_type"] == "vless_reality"


@pytest.mark.asyncio
async def test_unchanged_config_is_not_pushed_again(db_engine):
    factory = create_session_factory(db_engine)
    await _seed(factory)
    orch = _RecordingOrchestrator()
    sync = nus.NodeUserSync(factory, orch)
    await sync.sync_once()
    await sync.sync_once()
    assert len(orch.sent) == 1


@pytest.mark.asyncio
async def test_rejected_push_is_retried_next_cycle(db_engine):
    factory = create_session_factory(db_engine)
    await _seed(factory)
    orch = _RecordingOrchestrator(accept=False)
    sync = nus.NodeUserSync(factory, orch)
    await sync.sync_once()
    orch.accept = True
    await sync.sync_once()
    await sync.sync_once()
    assert len(orch.sent) == 2


@pytest.mark.asyncio
async def test_user_expiring_triggers_a_push_without_them(db_engine):
    factory = create_session_factory(db_engine)
    node, tokens = await _seed(factory)
    orch = _RecordingOrchestrator()
    sync = nus.NodeUserSync(factory, orch)
    await sync.sync_once()

    from sqlalchemy import update
    async with factory() as s:
        await s.execute(update(User).where(User.username == "ok")
                        .values(expire_date=datetime.now(timezone.utc) - timedelta(seconds=1)))
        await s.commit()
    await sync.sync_once()
    assert len(orch.sent) == 2
    assert _clients(orch.sent[1][1]) == set()


@pytest.mark.asyncio
async def test_nodes_without_a_private_key_are_skipped(db_engine):
    factory = create_session_factory(db_engine)
    async with factory() as s:
        s.add(Node(name="no-key", address="10.0.0.2", protocol=NodeProtocol.VLESS_REALITY))
        s.add(Node(name="awg", address="10.0.0.3", protocol=NodeProtocol.AMNEZIA_WG))
        await s.commit()
    orch = _RecordingOrchestrator()
    assert await nus.NodeUserSync(factory, orch).sync_once() == {}
    assert orch.sent == []


def test_request_user_sync_is_a_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(nus, "user_sync", None)
    nus.request_user_sync()  # must not raise


@pytest.mark.asyncio
async def test_user_api_changes_wake_the_sync(client, monkeypatch):
    from backend.tests.conftest import get_admin_token
    woken = []
    monkeypatch.setattr(nus, "user_sync", SimpleNamespace(request_sync=lambda: woken.append(1)))
    tok = await get_admin_token(client)
    auth = {"Authorization": f"Bearer {tok}"}
    user = (await client.post("/api/users/", json={"username": "wake", "password": "Password123!"},
                              headers=auth)).json()
    await client.patch(f"/api/users/{user['id']}", json={"is_active": False}, headers=auth)
    await client.post(f"/api/users/{user['id']}/regenerate-sub", headers=auth)
    await client.delete(f"/api/users/{user['id']}", headers=auth)
    assert len(woken) == 4


@pytest.mark.asyncio
async def test_end_to_end_against_the_real_agent(db_engine, tmp_path, monkeypatch):
    """The pushed config must be one the real agent accepts and writes."""
    import socket
    import ssl

    from aiohttp import web

    import agent.node_daemon as nd
    from backend.app.orchestrator import NodeOrchestrator

    factory = create_session_factory(db_engine)
    node, tokens = await _seed(factory)

    cfg_path = tmp_path / "xray.json"
    monkeypatch.setattr(nd, "resolve_target", lambda ct: (str(cfg_path), "xray"))

    async def _no_restart(service):
        return None
    monkeypatch.setattr(nd, "restart_service", _no_restart)
    cert, key = nd.ensure_tls_material(str(tmp_path / "tls"))
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]

    async with factory() as s:
        db_node = await s.get(Node, node.id)
        db_node.agent_port = port
        db_node.agent_cert_pem = open(cert, encoding="utf-8").read()
        monkeypatch.setattr(nd, "API_KEY", db_node.api_key)
        await s.commit()

    runner = web.AppRunner(nd.create_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ctx)
    await site.start()
    orch = NodeOrchestrator(db_session_factory=factory)
    try:
        result = await nus.NodeUserSync(factory, orch).sync_once()
    finally:
        await orch.stop()
        await runner.cleanup()

    assert result == {node.id: True}
    written = json.loads(cfg_path.read_text(encoding="utf-8"))
    ids = {c["id"] for i in written["inbounds"] if i["protocol"] == "vless" for c in i["settings"]["clients"]}
    assert ids == {derive_proxy_uuid(tokens["ok"], node.id)}

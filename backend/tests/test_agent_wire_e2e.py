"""
End-to-end: the real orchestrator talking to the real node agent over TLS
on localhost.

The master (backend/app/orchestrator.py) and the agent (agent/node_daemon.py)
are separate deployables that share no code, so nothing but a test like this
checks that their signing schemes and TLS setup actually agree. Before this,
they didn't: the orchestrator sent HTTPS to the node's *VPN* port while the
agent served plain HTTP on its own port.
"""

from __future__ import annotations

import socket
import ssl
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web

import agent.node_daemon as nd
from backend.app.orchestrator import NodeOrchestrator

API_KEY = "e2e-shared-node-key"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture
async def agent(tmp_path, monkeypatch):
    """A real agent on 127.0.0.1 with its own freshly generated certificate."""
    monkeypatch.setattr(nd, "API_KEY", API_KEY)
    cfg = tmp_path / "config.json"
    nd.atomic_write_config(str(cfg), {
        "inbounds": [{"port": 443, "protocol": "vless",
                      "settings": {"clients": [{"id": "alice", "email": "alice"}]}}],
        "outbounds": [{"protocol": "freedom"}],
    })
    monkeypatch.setattr(nd, "resolve_target", lambda ct: (str(cfg), "xray"))

    async def _no_restart(service):
        return None
    monkeypatch.setattr(nd, "restart_service", _no_restart)

    async def _no_traffic():
        return {}
    monkeypatch.setattr(nd, "get_amnezia_peer_traffic", _no_traffic)
    monkeypatch.setattr(nd, "get_xray_user_traffic", _no_traffic)

    cert_path, key_path = nd.ensure_tls_material(str(tmp_path / "tls"))
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, key_path)

    runner = web.AppRunner(nd.create_app())
    await runner.setup()
    port = _free_port()
    site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ctx)
    await site.start()
    try:
        yield SimpleNamespace(port=port, pem=open(cert_path, encoding="utf-8").read(), config=cfg)
    finally:
        await runner.cleanup()


def _node(agent, **kw):
    defaults = dict(id=1, name="e2e", address="127.0.0.1", port=443, agent_port=agent.port,
                    api_key=API_KEY, agent_cert_pem=agent.pem)
    defaults.update(kw)
    return SimpleNamespace(**defaults)


@pytest.mark.asyncio
async def test_health_check_succeeds_over_pinned_tls(agent):
    orch = NodeOrchestrator()
    failures = []

    async def _record(node_id):
        failures.append(node_id)
    orch._record_health_failure = _record

    await orch.check_node_health(_node(agent))
    await orch.stop()
    assert failures == []


@pytest.mark.asyncio
async def test_signed_command_is_applied_by_the_agent(agent):
    import json
    orch = NodeOrchestrator()
    ok = await orch.sync_node_config(_node(agent), {
        "config_type": "vless",
        "payload": {"action": "drop_user", "user_uuid": "alice"},
    })
    await orch.stop()
    assert ok is True
    clients = json.loads(agent.config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"]
    assert clients == []


@pytest.mark.asyncio
async def test_a_different_certificate_is_refused(agent, tmp_path):
    other_pem = open(nd.ensure_tls_material(str(tmp_path / "other"))[0], encoding="utf-8").read()
    orch = NodeOrchestrator()
    failures = []

    async def _record(node_id):
        failures.append(node_id)
    orch._record_health_failure = _record

    await orch.check_node_health(_node(agent, agent_cert_pem=other_pem))
    await orch.stop()
    assert failures == [1]


@pytest.mark.asyncio
async def test_wrong_api_key_is_refused(agent):
    orch = NodeOrchestrator()
    ok = await orch.sync_node_config(_node(agent, api_key="not-the-key"), {
        "config_type": "vless", "payload": {"action": "drop_user", "user_uuid": "alice"},
    })
    await orch.stop()
    assert ok is False


@pytest.mark.asyncio
async def test_trust_on_first_use_records_and_pins_the_agent_certificate(agent):
    orch = NodeOrchestrator()
    node = _node(agent, agent_cert_pem=None)
    pem = await orch._agent_cert(node)
    await orch.stop()
    assert nd.cert_fingerprint(pem) == nd.cert_fingerprint(agent.pem)
    assert node.agent_cert_pem == pem

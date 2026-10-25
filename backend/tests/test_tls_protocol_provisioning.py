"""
Hysteria2 / TUIC server provisioning.

These nodes used to be listed in subscriptions but nothing ever configured
the server side, and their links carried `sni` — a Reality cover domain the
node has no certificate for — so no client could verify the server.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from backend.app.api import subscriptions as subs
from backend.app.core import node_user_sync as nus
from backend.app.core.security import derive_proxy_uuid, hash_password
from backend.app.models import Node, NodeProtocol, Subscription, User, create_session_factory
from backend.app.schemas import NodeCreate, NodeUpdate
from backend.tests.conftest import get_admin_token


class _RecordingOrchestrator:
    def __init__(self):
        self.sent = []

    async def send_command(self, node, payload):
        self.sent.append((node.id, payload))
        return True


async def _seed(factory, protocol, tls_domain="de1.mtgroup.site"):
    async with factory() as s:
        node = Node(name=f"{protocol.value}-1", address="203.0.113.7", port=8443,
                    protocol=protocol, sni="www.samsung.com", tls_domain=tls_domain,
                    agent_cert_pem="PEM")
        s.add(node)
        ok = User(username="ok", hashed_password=hash_password("Password123!"))
        off = User(username="off", hashed_password=hash_password("Password123!"), is_active=False)
        s.add_all([ok, off])
        await s.flush()
        s.add_all([Subscription(user_id=ok.id, token="tok-ok"), Subscription(user_id=off.id, token="tok-off")])
        await s.commit()
        await s.refresh(node)
        return node


@pytest.mark.asyncio
async def test_hysteria2_node_gets_singbox_config_with_eligible_users(db_engine):
    factory = create_session_factory(db_engine)
    node = await _seed(factory, NodeProtocol.HYSTERIA2)
    orch = _RecordingOrchestrator()
    await nus.NodeUserSync(factory, orch).sync_once()

    (node_id, cmd), = orch.sent
    assert node_id == node.id
    assert cmd["config_type"].startswith("singbox")  # agent routes on this
    inbound, = cmd["payload"]["inbounds"]
    cred = derive_proxy_uuid("tok-ok", node.id)
    assert inbound["type"] == "hysteria2" and inbound["listen_port"] == 8443
    assert inbound["users"] == [{"name": cred, "password": cred}]
    assert inbound["tls"]["server_name"] == "de1.mtgroup.site"
    assert inbound["tls"]["certificate_path"] == nus.PUBLIC_TLS_CERT


@pytest.mark.asyncio
async def test_tuic_credentials_match_subscription(db_engine):
    factory = create_session_factory(db_engine)
    node = await _seed(factory, NodeProtocol.TUIC_V5)
    orch = _RecordingOrchestrator()
    await nus.NodeUserSync(factory, orch).sync_once()

    inbound, = orch.sent[0][1]["payload"]["inbounds"]
    cred = derive_proxy_uuid("tok-ok", node.id)
    assert inbound["type"] == "tuic"
    assert inbound["users"] == [{"name": cred, "uuid": cred, "password": cred[:16]}]

    # ...and the client side of the same subscription uses exactly these.
    out = subs.generate_tuic_singbox_config(address=node.address, port=node.port, user_uuid=cred,
                                            password=cred[:16], sni=subs._tls_sni(node))
    assert out["uuid"] == cred and out["password"] == cred[:16]
    assert out["tls"]["server_name"] == "de1.mtgroup.site"


@pytest.mark.asyncio
async def test_node_without_tls_domain_is_skipped(db_engine):
    factory = create_session_factory(db_engine)
    await _seed(factory, NodeProtocol.HYSTERIA2, tls_domain=None)
    orch = _RecordingOrchestrator()
    await nus.NodeUserSync(factory, orch).sync_once()
    assert orch.sent == []


@pytest.mark.asyncio
async def test_unchanged_config_is_not_pushed_twice(db_engine):
    factory = create_session_factory(db_engine)
    await _seed(factory, NodeProtocol.HYSTERIA2)
    orch = _RecordingOrchestrator()
    sync = nus.NodeUserSync(factory, orch)
    await sync.sync_once()
    await sync.sync_once()
    assert len(orch.sent) == 1


def test_server_config_blocks_private_destinations():
    node = Node(id=1, name="n", address="a", port=443, protocol=NodeProtocol.HYSTERIA2, tls_domain="x.example.com")
    cfg = nus.build_singbox_server_config(node, ["t"])
    rule, = cfg["route"]["rules"]
    assert rule["action"] == "reject" and "169.254.0.0/16" in rule["ip_cidr"]
    json.dumps(cfg)  # must be serialisable as-is


def test_tls_sni_prefers_tls_domain():
    assert subs._tls_sni(Node(sni="www.samsung.com", tls_domain="de1.mtgroup.site")) == "de1.mtgroup.site"
    assert subs._tls_sni(Node(sni="www.samsung.com", tls_domain=None)) == "www.samsung.com"


@pytest.mark.parametrize("value", ["https://de1.mtgroup.site", "de1.mtgroup.site:443", "de1 mtgroup.site",
                                   "-bad.mtgroup.site", "localhost", "a/b.com"])
def test_tls_domain_rejects_non_domains(value):
    with pytest.raises(ValidationError):
        NodeCreate(name="n", address="1.2.3.4", tls_domain=value)


def test_tls_domain_is_normalised_and_clearable():
    assert NodeCreate(name="n", address="1.2.3.4", tls_domain="DE1.MTGroup.site.").tls_domain == "de1.mtgroup.site"
    assert NodeUpdate(tls_domain="").tls_domain is None


@pytest.mark.asyncio
async def test_agent_setup_requires_and_includes_tls_domain(client):
    headers = {"Authorization": f"Bearer {await get_admin_token(client)}"}
    r = await client.post("/api/nodes", headers=headers, json={
        "name": "hy2", "address": "203.0.113.7", "port": 8443, "protocol": "hysteria2"})
    assert r.status_code == 201
    node_id = r.json()["id"]

    assert (await client.get(f"/api/nodes/{node_id}/agent-setup", headers=headers)).status_code == 400

    r = await client.patch(f"/api/nodes/{node_id}", headers=headers, json={"tls_domain": "de1.mtgroup.site"})
    assert r.status_code == 200 and r.json()["tls_domain"] == "de1.mtgroup.site"
    setup = (await client.get(f"/api/nodes/{node_id}/agent-setup", headers=headers)).json()
    assert "MTGROUP_TLS_DOMAIN='de1.mtgroup.site'" in setup["install_command"]

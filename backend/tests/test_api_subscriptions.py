"""
MTGroup VPN Ultimate — Subscriptions API Test Suite (gap-fill)
Covers endpoints not already exercised by test_api.py::TestSubscriptions:
plain GET /sub/{token} (client auto-detect), /amnezia, /qr, /links.
"""

from __future__ import annotations

import pytest

from backend.tests.conftest import get_admin_token


async def _create_user_with_sub_token(client, token, username="subgapuser"):
    resp = await client.post(
        "/api/users",
        json={"username": username, "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["subscription_token"]


class TestUniversalSubscription:
    @pytest.mark.asyncio
    async def test_default_user_agent_returns_singbox_json(self, client):
        token = await get_admin_token(client)
        sub_token = await _create_user_with_sub_token(client, token)

        resp = await client.get(f"/sub/{sub_token}")
        assert resp.status_code == 200
        assert "outbounds" in resp.json()

    @pytest.mark.asyncio
    async def test_clash_user_agent_returns_yaml(self, client):
        token = await get_admin_token(client)
        sub_token = await _create_user_with_sub_token(client, token, username="clashuadetect")

        resp = await client.get(f"/sub/{sub_token}", headers={"User-Agent": "Clash/1.0"})
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/yaml")

    @pytest.mark.asyncio
    async def test_404_for_invalid_token(self, client):
        resp = await client.get("/sub/does-not-exist")
        assert resp.status_code == 404


class TestQrCode:
    @pytest.mark.asyncio
    async def test_returns_png_image(self, client):
        token = await get_admin_token(client)
        sub_token = await _create_user_with_sub_token(client, token, username="qruser")

        resp = await client.get(f"/sub/{sub_token}/qr")
        assert resp.status_code == 200
        assert resp.headers["content-type"] in ("image/png", "text/plain")

    @pytest.mark.asyncio
    async def test_404_for_invalid_token(self, client):
        resp = await client.get("/sub/does-not-exist/qr")
        assert resp.status_code == 404


class TestRawLinks:
    @pytest.mark.asyncio
    async def test_returns_plaintext_links(self, client):
        token = await get_admin_token(client)
        sub_token = await _create_user_with_sub_token(client, token, username="linksuser")

        resp = await client.get(f"/sub/{sub_token}/links")
        assert resp.status_code == 200
        # The seeded test node is VLESS_REALITY (see conftest.client) and
        # the default user protocol list includes vless_reality, so at
        # least one vless:// link should be present.
        assert "vless://" in resp.text

    @pytest.mark.asyncio
    async def test_404_for_invalid_token(self, client):
        resp = await client.get("/sub/does-not-exist/links")
        assert resp.status_code == 404


class TestAmneziaConfig:
    @pytest.mark.asyncio
    async def test_503_when_no_amneziawg_nodes(self, client):
        """The default seeded node is VLESS_REALITY, not AMNEZIA_WG — the
        endpoint must fail predictably (503), not crash, when there's no
        matching backend to generate a config for."""
        token = await get_admin_token(client)
        sub_token = await _create_user_with_sub_token(client, token, username="amneziauser")

        resp = await client.get(f"/sub/{sub_token}/amnezia")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_503_when_node_has_no_wireguard_server_key(self, client):
        """
        A node flagged amnezia_wg but never provisioned has no WireGuard
        identity. Returning a config anyway would hand the user a file that
        silently never connects — which is exactly what used to happen, via
        `reality_public_key` standing in for a key the WG server never held.
        """
        token = await get_admin_token(client)
        await client.post(
            "/api/nodes",
            json={
                "name": "awg-unprovisioned", "address": "10.0.0.21", "port": 51820,
                "protocol": "amnezia_wg", "reality_public_key": "not-a-wg-key",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = await _create_user_with_sub_token(client, token, username="amnezia-unprov")

        resp = await client.get(f"/sub/{sub_token}/amnezia")
        assert resp.status_code == 503
        assert "provision" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_generates_conf_when_amneziawg_node_exists(self, client, monkeypatch):
        pushed = []

        async def _fake_sync(node, payload):
            pushed.append(payload)
            return True

        monkeypatch.setattr("backend.app.api.subscriptions.orchestrator.sync_node_config", _fake_sync)

        token = await get_admin_token(client)
        await client.post(
            "/api/nodes",
            json={
                "name": "awg-node", "address": "10.0.0.20", "port": 51820,
                "protocol": "amnezia_wg",
                "amnezia_server_public_key": "SERVERWGPUBKEY=",
                "amnezia_subnet": "10.8.0.0/24",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = await _create_user_with_sub_token(client, token, username="amneziauser2")

        resp = await client.get(f"/sub/{sub_token}/amnezia")
        assert resp.status_code == 200
        assert "[Interface]" in resp.text
        assert "[Peer]" in resp.text
        # The config must point at the WireGuard server key, not the Reality one.
        assert "PublicKey = SERVERWGPUBKEY=" in resp.text
        assert "Address = 10.8.0.2/32" in resp.text

        # And the node must have been told about this peer, or the tunnel
        # could never come up.
        assert len(pushed) == 1
        assert pushed[0]["payload"]["action"] == "add_peer"
        assert pushed[0]["payload"]["allowed_ips"] == "10.8.0.2/32"

    @pytest.mark.asyncio
    async def test_refetching_returns_the_same_keys(self, client, monkeypatch):
        """
        The regression that made this endpoint useless: each fetch minted a
        fresh keypair, so downloading the config twice invalidated whatever
        the user had already installed.
        """
        async def _fake_sync(node, payload):
            return True

        monkeypatch.setattr("backend.app.api.subscriptions.orchestrator.sync_node_config", _fake_sync)

        token = await get_admin_token(client)
        await client.post(
            "/api/nodes",
            json={
                "name": "awg-stable", "address": "10.0.0.22", "port": 51820,
                "protocol": "amnezia_wg", "amnezia_server_public_key": "SRV=",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = await _create_user_with_sub_token(client, token, username="amnezia-stable")

        first = await client.get(f"/sub/{sub_token}/amnezia")
        second = await client.get(f"/sub/{sub_token}/amnezia")

        assert first.status_code == second.status_code == 200
        assert first.text == second.text

    @pytest.mark.asyncio
    async def test_503_when_the_node_will_not_accept_the_peer(self, client, monkeypatch):
        """
        If the node can't be told about the peer, the config cannot work.
        Failing loudly beats handing over a file that never connects.
        """
        async def _failing_sync(node, payload):
            return False

        monkeypatch.setattr(
            "backend.app.api.subscriptions.orchestrator.sync_node_config", _failing_sync,
        )

        token = await get_admin_token(client)
        await client.post(
            "/api/nodes",
            json={
                "name": "awg-offline", "address": "10.0.0.23", "port": 51820,
                "protocol": "amnezia_wg", "amnezia_server_public_key": "SRV=",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = await _create_user_with_sub_token(client, token, username="amnezia-offline")

        resp = await client.get(f"/sub/{sub_token}/amnezia")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_retries_registration_after_an_earlier_failure(self, client, monkeypatch):
        """A failed push must not strand the allocation — the next fetch retries."""
        attempts = []

        async def _flaky_sync(node, payload):
            attempts.append(payload)
            return len(attempts) > 1  # fail the first time, succeed after

        monkeypatch.setattr("backend.app.api.subscriptions.orchestrator.sync_node_config", _flaky_sync)

        token = await get_admin_token(client)
        await client.post(
            "/api/nodes",
            json={
                "name": "awg-flaky", "address": "10.0.0.24", "port": 51820,
                "protocol": "amnezia_wg", "amnezia_server_public_key": "SRV=",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = await _create_user_with_sub_token(client, token, username="amnezia-flaky")

        assert (await client.get(f"/sub/{sub_token}/amnezia")).status_code == 503
        assert (await client.get(f"/sub/{sub_token}/amnezia")).status_code == 200
        assert len(attempts) == 2
        # Same peer both times — the failure didn't waste an address.
        assert attempts[0]["payload"]["public_key"] == attempts[1]["payload"]["public_key"]

    @pytest.mark.asyncio
    async def test_404_for_invalid_token(self, client):
        resp = await client.get("/sub/does-not-exist/amnezia")
        assert resp.status_code == 404

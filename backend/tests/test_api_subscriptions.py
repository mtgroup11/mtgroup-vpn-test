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
    async def test_generates_conf_when_amneziawg_node_exists(self, client):
        token = await get_admin_token(client)
        await client.post(
            "/api/nodes",
            json={
                "name": "awg-node", "address": "10.0.0.20", "port": 51820,
                "protocol": "amnezia_wg", "reality_public_key": "wgpubkey",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = await _create_user_with_sub_token(client, token, username="amneziauser2")

        resp = await client.get(f"/sub/{sub_token}/amnezia")
        assert resp.status_code == 200
        assert "[Interface]" in resp.text
        assert "[Peer]" in resp.text

    @pytest.mark.asyncio
    async def test_404_for_invalid_token(self, client):
        resp = await client.get("/sub/does-not-exist/amnezia")
        assert resp.status_code == 404

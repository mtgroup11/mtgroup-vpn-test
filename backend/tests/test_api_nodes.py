"""
MTGroup VPN Ultimate — Nodes API Test Suite (gap-fill)
Covers endpoints not already exercised by test_api.py::TestNodes:
GET /{id}, PATCH /{id}, DELETE /{id}, POST /{id}/redeploy-ip.
"""

from __future__ import annotations

import pytest

from backend.tests.conftest import get_admin_token


async def _create_node(client, token, **overrides):
    body = {
        "name": "gap-node",
        "address": "10.0.0.5",
        "port": 443,
        "protocol": "vless_reality",
        "sni": "www.google.com",
        "reality_public_key": "pubkey123",
        "reality_short_id": "short1",
    }
    body.update(overrides)
    resp = await client.post("/api/nodes", json=body, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestGetNode:
    @pytest.mark.asyncio
    async def test_returns_created_node(self, client):
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="getnode")
        resp = await client.get(f"/api/nodes/{created['id']}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "getnode"

    @pytest.mark.asyncio
    async def test_404_for_nonexistent_node(self, client):
        token = await get_admin_token(client)
        resp = await client.get("/api/nodes/999999", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404


class TestUpdateNode:
    @pytest.mark.asyncio
    async def test_partial_update(self, client):
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="updatenode", port=443)

        resp = await client.patch(
            f"/api/nodes/{created['id']}",
            json={"port": 8443},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["port"] == 8443
        assert resp.json()["name"] == "updatenode"  # untouched

    @pytest.mark.asyncio
    async def test_404_for_nonexistent_node(self, client):
        token = await get_admin_token(client)
        resp = await client.patch(
            "/api/nodes/999999", json={"port": 1234}, headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404


class TestDeleteNode:
    @pytest.mark.asyncio
    async def test_deletes_and_then_404s(self, client):
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="deleteme")

        del_resp = await client.delete(f"/api/nodes/{created['id']}", headers={"Authorization": f"Bearer {token}"})
        assert del_resp.status_code == 200

        get_resp = await client.get(f"/api/nodes/{created['id']}", headers={"Authorization": f"Bearer {token}"})
        assert get_resp.status_code == 404

    @pytest.mark.asyncio
    async def test_404_for_nonexistent_node(self, client):
        token = await get_admin_token(client)
        resp = await client.delete("/api/nodes/999999", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404


class TestRedeployIp:
    @pytest.mark.asyncio
    async def test_simulation_mode_assigns_new_ip_without_cloud_credentials(self, client):
        """No HETZNER_API_TOKEN/OVH creds are configured in the test env,
        so _provision_floating_ip() must fall back to its simulation-mode
        random-IP path rather than erroring."""
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="redeploynode")

        resp = await client.post(
            f"/api/nodes/{created['id']}/redeploy-ip",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "old=" in resp.json()["detail"]
        assert "new=" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_404_for_nonexistent_node(self, client):
        token = await get_admin_token(client)
        resp = await client.post(
            "/api/nodes/999999/redeploy-ip", headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404


class TestCreateNodeValidation:
    @pytest.mark.asyncio
    async def test_rejects_duplicate_name(self, client):
        token = await get_admin_token(client)
        await _create_node(client, token, name="dupenode")
        resp = await client.post(
            "/api/nodes",
            json={
                "name": "dupenode", "address": "10.0.0.9", "port": 443,
                "protocol": "vless_reality", "sni": "x.com",
                "reality_public_key": "k", "reality_short_id": "s",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 409

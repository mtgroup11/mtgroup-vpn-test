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
        "reality_short_id": "ab12cd34",
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
    async def test_without_cloud_credentials_refuses_instead_of_inventing_an_ip(self, client):
        """No HETZNER_API_TOKEN/OVH creds are configured in the test env.
        This used to save a random 10.x.x.x "simulated" address as the
        node's floating_ip, which every subscription then handed out."""
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="redeploynode")

        resp = await client.post(
            f"/api/nodes/{created['id']}/redeploy-ip",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400
        after = await client.get(f"/api/nodes/{created['id']}", headers={"Authorization": f"Bearer {token}"})
        assert after.json()["floating_ip"] is None

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
                "reality_public_key": "k", "reality_short_id": "ab",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 409


class TestAgentSetup:
    @pytest.mark.asyncio
    async def test_returns_the_api_key_and_install_command(self, client):
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="agentnode")
        resp = await client.get(f"/api/nodes/{created['id']}/agent-setup",
                                headers={"Authorization": f"Bearer {token}"})
        body = resp.json()
        assert resp.status_code == 200
        assert len(body["api_key"]) >= 32
        assert body["api_key"] in body["install_command"]
        assert body["agent_port"] == 8443
        assert "api_key" not in created  # never in the normal node payload

    @pytest.mark.asyncio
    async def test_requires_admin(self, client):
        resp = await client.get("/api/nodes/1/agent-setup")
        assert resp.status_code == 401


class TestAgentCertificatePin:
    @pytest.mark.asyncio
    async def test_pasted_certificate_is_stored_and_fingerprint_shown(self, client, tmp_path):
        import agent.node_daemon as nd
        cert, _ = nd.ensure_tls_material(str(tmp_path))
        pem = open(cert, encoding="utf-8").read()
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="pinnode")
        resp = await client.patch(f"/api/nodes/{created['id']}", json={"agent_cert_pem": pem, "agent_port": 9443},
                                  headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["agent_cert_fingerprint"] == nd.cert_fingerprint(pem)
        assert resp.json()["agent_port"] == 9443

        cleared = await client.patch(f"/api/nodes/{created['id']}", json={"agent_cert_pem": ""},
                                     headers={"Authorization": f"Bearer {token}"})
        assert cleared.json()["agent_cert_fingerprint"] is None

    @pytest.mark.asyncio
    async def test_garbage_certificate_is_422(self, client):
        token = await get_admin_token(client)
        created = await _create_node(client, token, name="badpin")
        resp = await client.patch(f"/api/nodes/{created['id']}", json={"agent_cert_pem": "not a cert"},
                                  headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 422


class TestNodeValidation:
    @pytest.mark.asyncio
    async def test_non_hex_short_id_is_422(self, client):
        token = await get_admin_token(client)
        resp = await client.post("/api/nodes", json={"name": "badsid", "address": "10.0.0.3",
                                                     "reality_short_id": "short1"},
                                 headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_amnezia_params_are_422_not_a_later_500(self, client):
        token = await get_admin_token(client)
        resp = await client.post("/api/nodes", json={
            "name": "awg-bad", "address": "10.0.0.4", "port": 51820, "protocol": "amnezia_wg",
            "amnezia_s1": 10, "amnezia_s2": 66,
        }, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 422

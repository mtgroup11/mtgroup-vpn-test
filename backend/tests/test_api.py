"""
MTGroup VPN Ultimate — API Test Suite
Comprehensive tests for all API endpoints using httpx + pytest-asyncio.
"""

from __future__ import annotations


import pytest

from backend.tests.conftest import get_admin_token


# ---------------------------------------------------------------------------
# Auth Tests
# ---------------------------------------------------------------------------

class TestAuth:
    @pytest.mark.asyncio
    async def test_login_success(self, client):
        response = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "TestAdmin123!"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, client):
        response = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrongpass"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        response = await client.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "anything"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_token(self, client):
        login_resp = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "TestAdmin123!"},
        )
        refresh_token = login_resp.json()["refresh_token"]

        response = await client.post(
            "/api/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

    @pytest.mark.asyncio
    async def test_protected_route_without_token(self, client):
        response = await client.get("/api/auth/me")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_route_with_token(self, client):
        token = await get_admin_token(client)
        response = await client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# User CRUD Tests
# ---------------------------------------------------------------------------

class TestUsers:
    @pytest.mark.asyncio
    async def test_create_user(self, client):
        token = await get_admin_token(client)
        response = await client.post(
            "/api/users",
            json={
                "username": "testuser",
                "password": "TestPass123!",
                "expire_days": 30,
                "data_limit_bytes": 53687091200,  # 50 GB
                "protocols": ["vless_reality", "hysteria2"],
                "iran_bypass": True,
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "testuser"
        assert data["subscription_token"] is not None

    @pytest.mark.asyncio
    async def test_create_duplicate_user(self, client):
        token = await get_admin_token(client)
        await client.post(
            "/api/users",
            json={"username": "dup", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        response = await client.post(
            "/api/users",
            json={"username": "dup", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 409

    @pytest.mark.asyncio
    async def test_list_users(self, client):
        token = await get_admin_token(client)
        response = await client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_update_user(self, client):
        token = await get_admin_token(client)
        # Create user first
        create_resp = await client.post(
            "/api/users",
            json={"username": "updateme", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        user_id = create_resp.json()["id"]

        # Update
        response = await client.patch(
            f"/api/users/{user_id}",
            json={"is_active": False, "bandwidth_limit_mbps": 25},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is False
        assert response.json()["bandwidth_limit_mbps"] == 25

    @pytest.mark.asyncio
    async def test_delete_user(self, client):
        token = await get_admin_token(client)
        create_resp = await client.post(
            "/api/users",
            json={"username": "deleteme", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        user_id = create_resp.json()["id"]

        response = await client.delete(
            f"/api/users/{user_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_reset_traffic(self, client):
        token = await get_admin_token(client)
        create_resp = await client.post(
            "/api/users",
            json={"username": "trafficuser", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        user_id = create_resp.json()["id"]

        response = await client.post(
            f"/api/users/{user_id}/reset-traffic",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        assert response.json()["data_used_bytes"] == 0


# ---------------------------------------------------------------------------
# Subscription Tests
# ---------------------------------------------------------------------------

class TestSubscriptions:
    @pytest.mark.asyncio
    async def test_get_v2ray_links(self, client):
        token = await get_admin_token(client)
        create_resp = await client.post(
            "/api/users",
            json={"username": "subuser", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = create_resp.json()["subscription_token"]

        response = await client.get(f"/sub/{sub_token}/v2ray")
        assert response.status_code == 200
        assert "Subscription-Userinfo" in response.headers

    @pytest.mark.asyncio
    async def test_get_singbox_config(self, client):
        token = await get_admin_token(client)
        create_resp = await client.post(
            "/api/users",
            json={"username": "singboxuser", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = create_resp.json()["subscription_token"]

        response = await client.get(f"/sub/{sub_token}/singbox")
        assert response.status_code == 200
        config = response.json()
        assert "dns" in config
        assert "outbounds" in config
        assert "route" in config

    @pytest.mark.asyncio
    async def test_get_clash_config(self, client):
        token = await get_admin_token(client)
        create_resp = await client.post(
            "/api/users",
            json={"username": "clashuser", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0},
            headers={"Authorization": f"Bearer {token}"},
        )
        sub_token = create_resp.json()["subscription_token"]

        response = await client.get(f"/sub/{sub_token}/clash")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/yaml")

    @pytest.mark.asyncio
    async def test_invalid_subscription_token(self, client):
        response = await client.get("/sub/invalid_token_here/v2ray")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Node Tests
# ---------------------------------------------------------------------------

class TestNodes:
    @pytest.mark.asyncio
    async def test_list_nodes(self, client):
        token = await get_admin_token(client)
        response = await client.get(
            "/api/nodes",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_create_node(self, client):
        token = await get_admin_token(client)
        response = await client.post(
            "/api/nodes",
            json={
                "name": "new-node",
                "address": "192.168.1.1",
                "port": 8443,
                "protocol": "hysteria2",
                "sni": "example.com",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        assert response.json()["name"] == "new-node"

    @pytest.mark.asyncio
    async def test_port_hop(self, client):
        token = await get_admin_token(client)
        nodes_resp = await client.get(
            "/api/nodes",
            headers={"Authorization": f"Bearer {token}"},
        )
        node_id = nodes_resp.json()["nodes"][0]["id"]

        response = await client.post(
            f"/api/nodes/{node_id}/port-hop",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# System Tests
# ---------------------------------------------------------------------------

class TestSystem:
    @pytest.mark.asyncio
    async def test_system_stats(self, client):
        token = await get_admin_token(client)
        response = await client.get(
            "/api/system/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "cpu_percent" in data
        assert "total_users" in data

    @pytest.mark.asyncio
    async def test_ban_ip(self, client):
        token = await get_admin_token(client)
        response = await client.post(
            "/api/system/bans",
            json={"ip_address": "192.168.1.100", "reason": "manual", "duration_hours": 24},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# Rate Limiter Tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_token_bucket(self):
        from backend.app.core.security import TokenBucketRateLimiter

        limiter = TokenBucketRateLimiter(max_tokens=3, refill_rate=0)
        assert limiter.is_allowed("test_ip")
        assert limiter.is_allowed("test_ip")
        assert limiter.is_allowed("test_ip")
        assert not limiter.is_allowed("test_ip")  # Should be blocked

    def test_login_tracker(self):
        from backend.app.core.security import LoginAttemptTracker

        tracker = LoginAttemptTracker(max_attempts=3, window_seconds=300)
        assert not tracker.record_failure("1.2.3.4")
        assert not tracker.record_failure("1.2.3.4")
        assert tracker.record_failure("1.2.3.4")  # 3rd attempt → should ban
        assert tracker.is_blocked("1.2.3.4")

    def test_login_success_clears_failures(self):
        from backend.app.core.security import LoginAttemptTracker

        tracker = LoginAttemptTracker(max_attempts=5, window_seconds=300)
        tracker.record_failure("5.6.7.8")
        tracker.record_failure("5.6.7.8")
        tracker.record_success("5.6.7.8")
        assert tracker.get_attempts("5.6.7.8") == 0


# ---------------------------------------------------------------------------
# Generator Tests
# ---------------------------------------------------------------------------

class TestGenerators:
    def test_vless_reality_link(self):
        from backend.app.generators.generator_vless import generate_vless_reality_link

        link = generate_vless_reality_link(
            address="10.0.0.1",
            port=443,
            user_uuid="test-uuid",
            public_key="test_pub_key",
            sni="www.google.com",
        )
        assert link.startswith("vless://")
        assert "test-uuid" in link
        assert "reality" in link
        assert "fragment" in link  # TLS fragment should be enabled by default

    def test_hysteria2_link(self):
        from backend.app.generators.generator_hysteria2 import generate_hysteria2_link

        link = generate_hysteria2_link(
            address="10.0.0.1",
            port=443,
            password="test_password",
            sni="example.com",
        )
        assert link.startswith("hysteria2://")
        assert "test_password" in link

    def test_tuic_link(self):
        from backend.app.generators.generator_tuic import generate_tuic_link

        link = generate_tuic_link(
            address="10.0.0.1",
            port=443,
            password="test_pass",
        )
        assert link.startswith("tuic://")
        assert "bbr" in link

    def test_amnezia_conf(self):
        from backend.app.generators.generator_amnezia import generate_amnezia_conf

        conf = generate_amnezia_conf(
            server_public_key="test_pub_key_base64==",
            server_endpoint="10.0.0.1",
            server_port=51820,
            jc=8,
            jmin=50,
            jmax=100,
        )
        assert "[Interface]" in conf
        assert "[Peer]" in conf
        assert "Jc = 8" in conf
        assert "Jmin = 50" in conf
        assert "Jmax = 100" in conf

    def test_singbox_config_with_iran_bypass(self):
        from backend.app.generators.generator_singbox import generate_singbox_config

        config = generate_singbox_config(
            outbounds=[{
                "type": "vless",
                "tag": "test-vless",
                "server": "10.0.0.1",
                "server_port": 443,
                "uuid": "test-uuid",
            }],
            iran_bypass=True,
            gamer_mode=True,
        )
        assert "dns" in config
        assert "route" in config
        rules = config["route"]["rules"]
        # Check Iran bypass rules exist
        iran_rules = [r for r in rules if r.get("outbound") == "direct" and ".ir" in str(r)]
        assert len(iran_rules) > 0

    def test_clash_config(self):
        from backend.app.generators.generator_clash import generate_clash_config

        yaml_str = generate_clash_config(
            proxies=[{
                "name": "Test-VLESS",
                "type": "vless",
                "server": "10.0.0.1",
                "port": 443,
                "uuid": "test-uuid",
            }],
            iran_bypass=True,
        )
        assert "proxies:" in yaml_str or "proxy-groups:" in yaml_str

    def test_port_hopper(self):
        from backend.app.generators.port_hopper import PortHopper

        hopper = PortHopper(
            low_ports=[80, 443],
            high_port_start=50000,
            high_port_end=50100,
            hop_interval_sec=0,
        )
        port1 = hopper.get_current_port()
        port2 = hopper.force_hop()
        assert isinstance(port1, int)
        assert isinstance(port2, int)
        assert port1 != port2 or len(hopper._combined_pool) == 1

    def test_traffic_shaper(self):
        from backend.app.generators.traffic_shaper import TrafficShaper, ShapingMode

        shaper = TrafficShaper(ShapingMode.VIDEO_STREAM)
        schedule = shaper.generate_chaff_schedule(duration_sec=1.0)
        assert len(schedule) > 0
        assert all("delay_ms" in s and "size_bytes" in s for s in schedule)

        params = shaper.get_jitter_params()
        assert params["jitter_enabled"] is True

        modes = TrafficShaper.get_available_modes()
        assert len(modes) == 5

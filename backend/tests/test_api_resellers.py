"""
MTGroup VPN Ultimate — Resellers API Test Suite
Covers POST /api/resellers/sub-agents and GET /api/resellers/sub-agents
(previously entirely untested — 0% coverage on api/resellers.py).
"""

from __future__ import annotations

import pytest

from backend.tests.conftest import get_admin_token


class TestCreateSubAgent:
    @pytest.mark.asyncio
    async def test_admin_can_create_sub_agent(self, client):
        token = await get_admin_token(client)
        resp = await client.post(
            "/api/resellers/sub-agents",
            json={"username": "reseller1", "password": "TestPass123!", "traffic_quota_mb": 1024},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "success"
        assert body["allocated_mb"] == 1024
        assert "agent_code" in body

    @pytest.mark.asyncio
    async def test_rejects_duplicate_username(self, client):
        token = await get_admin_token(client)
        await client.post(
            "/api/resellers/sub-agents",
            json={"username": "dupereseller", "password": "TestPass123!", "traffic_quota_mb": 500},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = await client.post(
            "/api/resellers/sub-agents",
            json={"username": "dupereseller", "password": "TestPass123!", "traffic_quota_mb": 500},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_requires_auth(self, client):
        resp = await client.post(
            "/api/resellers/sub-agents",
            json={"username": "noauth", "password": "TestPass123!", "traffic_quota_mb": 500},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_plain_user_role_forbidden(self, client, db_engine):
        """A regular USER-role account (not ADMIN/RESELLER) must not be
        able to create sub-agents."""
        from backend.app.core.security import create_access_token, hash_password
        from backend.app.models import User, UserRole, create_session_factory

        factory = create_session_factory(db_engine)
        async with factory() as session:
            plain_user = User(username="plainuser", hashed_password=hash_password("x"), role=UserRole.USER, is_active=True)
            session.add(plain_user)
            await session.commit()
            await session.refresh(plain_user)

        plain_token = create_access_token(
            {"sub": str(plain_user.id), "username": plain_user.username, "role": plain_user.role.value}
        )

        resp = await client.post(
            "/api/resellers/sub-agents",
            json={"username": "shouldfail", "password": "TestPass123!", "traffic_quota_mb": 500},
            headers={"Authorization": f"Bearer {plain_token}"},
        )
        assert resp.status_code == 403


class TestListSubAgents:
    @pytest.mark.asyncio
    async def test_admin_sees_top_level_agents(self, client):
        token = await get_admin_token(client)
        await client.post(
            "/api/resellers/sub-agents",
            json={"username": "listedreseller", "password": "TestPass123!", "traffic_quota_mb": 200},
            headers={"Authorization": f"Bearer {token}"},
        )

        resp = await client.get("/api/resellers/sub-agents", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert len(resp.json()) >= 1
        assert resp.json()[0]["quota_bytes"] == 200 * 1024 * 1024

    @pytest.mark.asyncio
    async def test_requires_auth(self, client):
        resp = await client.get("/api/resellers/sub-agents")
        assert resp.status_code in (401, 403)

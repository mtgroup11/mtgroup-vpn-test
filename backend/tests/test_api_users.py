"""
MTGroup VPN Ultimate — Users API Test Suite (gap-fill)
Covers endpoints not already exercised by test_api.py::TestUsers:
GET /{id}, POST /{id}/regenerate-sub, and 404/validation edge cases.
"""

from __future__ import annotations

import pytest

from backend.tests.conftest import get_admin_token


async def _create_user(client, token, **overrides):
    body = {"username": "gapuser", "password": "TestPass123!", "expire_days": 30, "data_limit_bytes": 0}
    body.update(overrides)
    resp = await client.post("/api/users", json=body, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201, resp.text
    return resp.json()


class TestGetUser:
    @pytest.mark.asyncio
    async def test_returns_created_user(self, client):
        token = await get_admin_token(client)
        created = await _create_user(client, token, username="getme")

        resp = await client.get(f"/api/users/{created['id']}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "getme"

    @pytest.mark.asyncio
    async def test_404_for_nonexistent_user(self, client):
        token = await get_admin_token(client)
        resp = await client.get("/api/users/999999", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_requires_auth(self, client):
        resp = await client.get("/api/users/1")
        assert resp.status_code in (401, 403)


class TestRegenerateSub:
    @pytest.mark.asyncio
    async def test_regenerates_subscription_token(self, client):
        token = await get_admin_token(client)
        created = await _create_user(client, token, username="regenme")
        old_sub_token = created["subscription_token"]

        resp = await client.post(
            f"/api/users/{created['id']}/regenerate-sub",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        new_sub_token = resp.json()["subscription_token"]
        assert new_sub_token != old_sub_token

    @pytest.mark.asyncio
    async def test_old_subscription_token_stops_working_after_regen(self, client):
        token = await get_admin_token(client)
        created = await _create_user(client, token, username="regenold")
        old_sub_token = created["subscription_token"]

        await client.post(
            f"/api/users/{created['id']}/regenerate-sub",
            headers={"Authorization": f"Bearer {token}"},
        )

        resp = await client.get(f"/sub/{old_sub_token}/v2ray")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_404_for_nonexistent_user(self, client):
        token = await get_admin_token(client)
        resp = await client.post("/api/users/999999/regenerate-sub", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404


class TestCreateUserValidation:
    @pytest.mark.asyncio
    async def test_rejects_short_password(self, client):
        token = await get_admin_token(client)
        resp = await client.post(
            "/api/users",
            json={"username": "shortpw", "password": "abc", "expire_days": 30},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_rejects_short_username(self, client):
        token = await get_admin_token(client)
        resp = await client.post(
            "/api/users",
            json={"username": "ab", "password": "TestPass123!", "expire_days": 30},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422


class TestUpdateUserPartial:
    @pytest.mark.asyncio
    async def test_partial_update_leaves_other_fields_untouched(self, client):
        token = await get_admin_token(client)
        created = await _create_user(client, token, username="partialupdate", data_limit_bytes=1000)

        resp = await client.patch(
            f"/api/users/{created['id']}",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_active"] is False
        assert body["data_limit_bytes"] == 1000  # untouched by the partial update

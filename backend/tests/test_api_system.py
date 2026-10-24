"""
MTGroup VPN Ultimate — System API Test Suite (gap-fill)
Covers endpoints not already exercised by test_api.py::TestSystem:
GET/PUT /config, GET /bans, DELETE /bans/{ip}.
"""

from __future__ import annotations

import pytest

from backend.tests.conftest import get_admin_token


class TestSystemConfig:
    @pytest.mark.asyncio
    async def test_put_then_get_round_trips(self, client):
        token = await get_admin_token(client)

        put_resp = await client.put(
            "/api/system/config",
            json={"key": "test_setting", "value": "hello", "description": "a test setting"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert put_resp.status_code == 200
        assert put_resp.json()["key"] == "test_setting"

        get_resp = await client.get("/api/system/config", headers={"Authorization": f"Bearer {token}"})
        assert get_resp.status_code == 200
        keys = [c["key"] for c in get_resp.json()]
        assert "test_setting" in keys

    @pytest.mark.asyncio
    async def test_put_overwrites_existing_key(self, client):
        token = await get_admin_token(client)
        await client.put(
            "/api/system/config",
            json={"key": "overwrite_me", "value": "v1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = await client.put(
            "/api/system/config",
            json={"key": "overwrite_me", "value": "v2"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["value"] == "v2"

    @pytest.mark.asyncio
    async def test_requires_admin(self, client):
        resp = await client.get("/api/system/config")
        assert resp.status_code in (401, 403)


class TestBanManagement:
    @pytest.mark.asyncio
    async def test_list_bans_includes_created_ban(self, client):
        token = await get_admin_token(client)
        create_resp = await client.post(
            "/api/system/bans",
            json={"ip_address": "203.0.113.55", "reason": "manual", "duration_hours": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert create_resp.status_code == 200, create_resp.text

        resp = await client.get("/api/system/bans", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        ips = [b["ip_address"] for b in resp.json()]
        assert "203.0.113.55" in ips

    @pytest.mark.asyncio
    async def test_unban_removes_from_list(self, client):
        token = await get_admin_token(client)
        create_resp = await client.post(
            "/api/system/bans",
            json={"ip_address": "203.0.113.66", "reason": "manual", "duration_hours": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert create_resp.status_code == 200, create_resp.text

        del_resp = await client.delete(
            "/api/system/bans/203.0.113.66", headers={"Authorization": f"Bearer {token}"},
        )
        assert del_resp.status_code == 200

        resp = await client.get("/api/system/bans", headers={"Authorization": f"Bearer {token}"})
        ips = [b["ip_address"] for b in resp.json()]
        assert "203.0.113.66" not in ips

    @pytest.mark.asyncio
    async def test_invalid_reason_rejected_with_422_not_500(self, client):
        """Regression test: `reason` used to be a plain `str` that only
        the DB layer validated (via SQLAlchemy's Enum column), so a
        client-supplied value that wasn't an exact BanReason match blew
        up as an unhandled 500 instead of a clean validation error."""
        token = await get_admin_token(client)
        resp = await client.post(
            "/api/system/bans",
            json={"ip_address": "203.0.113.88", "reason": "not_a_real_reason", "duration_hours": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_omitted_reason_defaults_to_manual(self, client):
        token = await get_admin_token(client)
        resp = await client.post(
            "/api/system/bans",
            json={"ip_address": "203.0.113.99", "duration_hours": 1},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["reason"] == "manual"

    @pytest.mark.asyncio
    async def test_unban_nonexistent_ip_returns_404(self, client):
        token = await get_admin_token(client)
        resp = await client.delete(
            "/api/system/bans/198.51.100.1", headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_bandwidth_is_a_rate_not_a_cumulative_total(client, monkeypatch):
    from types import SimpleNamespace

    import backend.app.api.system as system_mod
    from backend.tests.conftest import get_admin_token

    counters = iter([(0, 0), (1_250_000, 2_500_000)])  # +10 Mbit up, +20 Mbit down
    clock = iter([100.0, 101.0])

    def fake_counters():
        sent, recv = next(counters)
        return SimpleNamespace(bytes_sent=10**12 + sent, bytes_recv=10**12 + recv)

    import psutil
    monkeypatch.setattr(psutil, "net_io_counters", fake_counters)
    monkeypatch.setattr(system_mod, "_clock", lambda: next(clock))
    system_mod._last_net_sample.clear()
    auth = {"Authorization": f"Bearer {await get_admin_token(client)}"}
    first = (await client.get("/api/system/stats", headers=auth)).json()
    second = (await client.get("/api/system/stats", headers=auth)).json()
    assert first["bandwidth_up_mbps"] == 0  # no previous sample yet
    assert second["bandwidth_up_mbps"] == pytest.approx(10.0)
    assert second["bandwidth_down_mbps"] == pytest.approx(20.0)

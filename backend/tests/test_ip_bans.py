"""
IP bans against a real database: persistence, restore on restart, upsert
on repeat offenders, and the admin API's view of honeypot/AI bans.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from backend.app.core.crypto_quantum import hash_for_lookup
from backend.app.models import BannedIP, BanReason, create_session_factory
from backend.app.orchestrator import NodeOrchestrator
from backend.tests.conftest import get_admin_token


@pytest.fixture
def no_ebpf(monkeypatch):
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "EBPF_ENABLED", False)


async def _rows(factory):
    async with factory() as s:
        return (await s.execute(select(BannedIP))).scalars().all()


@pytest.mark.asyncio
async def test_security_alert_bans_and_persists_with_the_api_hash(db_engine, no_ebpf):
    factory = create_session_factory(db_engine)
    orch = NodeOrchestrator(db_session_factory=factory)
    await orch.handle_security_alert("203.0.113.3", "anomalous traffic spike")
    rows = await _rows(factory)
    assert orch.is_app_banned("203.0.113.3")
    assert len(rows) == 1
    # Same hash the admin API looks up with — plain sha256 made these
    # bans impossible to find or lift through the API.
    assert rows[0].ip_hash == hash_for_lookup("203.0.113.3")
    assert rows[0].details == "anomalous traffic spike"
    assert len(orch._ban_tasks) == 1
    await orch.stop()


@pytest.mark.asyncio
async def test_repeat_offender_extends_instead_of_failing(db_engine, no_ebpf):
    factory = create_session_factory(db_engine)
    orch = NodeOrchestrator(db_session_factory=factory)
    await orch.handle_security_alert("203.0.113.9", "first")
    first_expiry = (await _rows(factory))[0].expires_at
    await orch.handle_security_alert("203.0.113.9", "second")
    rows = await _rows(factory)
    assert len(rows) == 1
    assert rows[0].details == "second"
    assert rows[0].expires_at >= first_expiry
    # The second alert used to raise IntegrityError before scheduling its
    # TTL, so the IP stayed banned until restart.
    assert len(orch._ban_tasks) == 2
    await orch.stop()


@pytest.mark.asyncio
async def test_restore_reapplies_only_unexpired_bans(db_engine, no_ebpf):
    factory = create_session_factory(db_engine)
    now = datetime.now(timezone.utc)
    async with factory() as s:
        for ip, expires in (("198.51.100.1", now + timedelta(hours=1)),
                            ("198.51.100.2", now - timedelta(hours=1)),
                            ("198.51.100.3", None)):
            s.add(BannedIP(ip_address=ip, ip_hash=hash_for_lookup(ip), reason=BanReason.MANUAL, expires_at=expires))
        await s.commit()

    fresh = NodeOrchestrator(db_session_factory=factory)  # i.e. after a restart
    assert await fresh.restore_bans() == 2
    assert fresh.is_app_banned("198.51.100.1")
    assert not fresh.is_app_banned("198.51.100.2")
    assert fresh.is_app_banned("198.51.100.3")
    await fresh.stop()


@pytest.mark.asyncio
async def test_stale_timer_does_not_lift_an_extended_ban(db_engine, no_ebpf, monkeypatch):
    factory = create_session_factory(db_engine)
    orch = NodeOrchestrator(db_session_factory=factory)
    ip = "203.0.113.20"
    async with factory() as s:
        s.add(BannedIP(ip_address=ip, ip_hash=hash_for_lookup(ip), reason=BanReason.MANUAL,
                       expires_at=datetime.now(timezone.utc) + timedelta(hours=2)))
        await s.commit()
    await orch.apply_ip_ban(ip)

    async def _instant(_):
        return None
    monkeypatch.setattr("backend.app.orchestrator.asyncio.sleep", _instant)
    await orch._remove_ban_after_ttl(ip, 300)  # an old 5-minute timer firing
    assert orch.is_app_banned(ip)
    await orch.stop()


@pytest.mark.asyncio
async def test_api_can_reban_after_expiry_and_rejects_non_ips(client, db_engine):
    tok = await get_admin_token(client)
    auth = {"Authorization": f"Bearer {tok}"}
    factory = create_session_factory(db_engine)
    async with factory() as s:
        s.add(BannedIP(ip_address="192.0.2.50", ip_hash=hash_for_lookup("192.0.2.50"), reason=BanReason.MANUAL,
                       expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
        await s.commit()

    resp = await client.post("/api/system/bans", json={"ip_address": " 192.0.2.50 "}, headers=auth)
    assert resp.status_code == 200, resp.text
    again = await client.post("/api/system/bans", json={"ip_address": "192.0.2.50"}, headers=auth)
    assert again.status_code == 409

    bad = await client.post("/api/system/bans", json={"ip_address": "not-an-ip; rm -rf /"}, headers=auth)
    assert bad.status_code == 422

    lifted = await client.delete("/api/system/bans/192.0.2.50", headers=auth)
    assert lifted.status_code == 200


@pytest.mark.asyncio
async def test_honeypot_ban_is_visible_and_liftable_through_the_api(client, db_engine, no_ebpf):
    from backend.app.orchestrator import orchestrator
    factory = create_session_factory(db_engine)
    saved = orchestrator._db_session_factory
    orchestrator._db_session_factory = factory
    try:
        await orchestrator.handle_security_alert("192.0.2.77", "LETHAL_PROBE")
        tok = await get_admin_token(client)
        auth = {"Authorization": f"Bearer {tok}"}
        listed = (await client.get("/api/system/bans", headers=auth)).json()
        assert any(b["ip_address"] == "192.0.2.77" for b in listed)
        assert (await client.delete("/api/system/bans/192.0.2.77", headers=auth)).status_code == 200
        assert not orchestrator.is_app_banned("192.0.2.77")
    finally:
        for task in list(orchestrator._ban_tasks):
            task.cancel()
        orchestrator._db_session_factory = saved

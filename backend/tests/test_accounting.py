"""
MTGroup VPN Ultimate — Traffic Accounting Engine Test Suite (partial)
Covers `ingest_traffic`'s buffering logic, which is pure and needs no DB —
`_process_accounting`'s bulk-update/quota-suspension path involves several
chained SQLAlchemy statements and is left for a future, more thorough pass.
"""

from __future__ import annotations

import pytest

from backend.app.core.accounting import TrafficAccountingEngine


@pytest.fixture
def engine():
    return TrafficAccountingEngine(db_session_factory=lambda: None)


class TestIngestTraffic:
    @pytest.mark.asyncio
    async def test_accumulates_across_multiple_calls(self, engine):
        await engine.ingest_traffic(user_id=1, bytes_delta=100)
        await engine.ingest_traffic(user_id=1, bytes_delta=250)
        assert engine._traffic_buffer[1] == 350

    @pytest.mark.asyncio
    async def test_tracks_separate_users_independently(self, engine):
        await engine.ingest_traffic(user_id=1, bytes_delta=100)
        await engine.ingest_traffic(user_id=2, bytes_delta=200)
        assert engine._traffic_buffer == {1: 100, 2: 200}

    @pytest.mark.asyncio
    async def test_ignores_zero_or_negative_delta(self, engine):
        await engine.ingest_traffic(user_id=1, bytes_delta=0)
        await engine.ingest_traffic(user_id=1, bytes_delta=-50)
        assert 1 not in engine._traffic_buffer

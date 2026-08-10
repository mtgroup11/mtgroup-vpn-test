"""
MTGroup VPN Ultimate — Payment Tracker Engine Test Suite
Tests backend/app/core/payments.py's TON/TRX deposit verification,
replay-attack protection, and subscription-extension logic, with the
Web3 HTTP calls and DB session mocked out.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.core.payments import MIN_PAYMENT_USDT, PaymentTrackerEngine


def _make_user(**overrides):
    defaults = dict(
        username="alice",
        crypto_address_ton=None,
        crypto_address_trx=None,
        expire_date=None,
        data_limit_bytes=0,
        is_active=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class _FakeAiohttpResponse:
    def __init__(self, status: int, json_body: dict):
        self.status = status
        self._json_body = json_body

    async def json(self):
        return self._json_body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeAiohttpSession:
    """`session.get(url, params=..., timeout=...)` returns an async
    context manager — this fake reproduces exactly that shape."""

    def __init__(self, response: _FakeAiohttpResponse):
        self._response = response
        self.last_url = None
        self.last_params = None

    def get(self, url, params=None, timeout=None):
        self.last_url = url
        self.last_params = params
        return self._response


@pytest.fixture
def engine():
    return PaymentTrackerEngine(db_session_factory=lambda: AsyncMock())


class TestIsTxProcessed:
    @pytest.mark.asyncio
    async def test_returns_true_when_row_exists(self, engine):
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=object()))
        assert await engine._is_tx_processed(db, "abc123") is True

    @pytest.mark.asyncio
    async def test_returns_false_when_no_row(self, engine):
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        assert await engine._is_tx_processed(db, "abc123") is False


class TestCheckTonAddress:
    @pytest.mark.asyncio
    async def test_credits_subscription_on_valid_deposit_above_minimum(self, engine, monkeypatch):
        user = _make_user(crypto_address_ton="EQ_test")
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))  # not yet processed

        response = _FakeAiohttpResponse(200, {
            "ok": True,
            "result": [
                {"transaction_id": {"hash": "tx-1"}, "in_msg": {"value": str(int(2 * 1e9))}},  # 2 TON
            ],
        })
        session = _FakeAiohttpSession(response)

        extended = AsyncMock()
        monkeypatch.setattr(engine, "_extend_user_subscription", extended)

        await engine._check_ton_address(session, db, user)
        extended.assert_awaited_once()
        args = extended.await_args.args
        assert args[1] is user
        assert args[2] == "TON"
        assert args[3] == pytest.approx(2.0)
        assert args[4] == "tx-1"

    @pytest.mark.asyncio
    async def test_ignores_deposit_below_minimum(self, engine, monkeypatch):
        user = _make_user(crypto_address_ton="EQ_test")
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))

        below_min = MIN_PAYMENT_USDT / 2
        response = _FakeAiohttpResponse(200, {
            "ok": True,
            "result": [{"transaction_id": {"hash": "tx-2"}, "in_msg": {"value": str(int(below_min * 1e9))}}],
        })
        session = _FakeAiohttpSession(response)

        extended = AsyncMock()
        monkeypatch.setattr(engine, "_extend_user_subscription", extended)

        await engine._check_ton_address(session, db, user)
        extended.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_already_processed_transaction_replay_protection(self, engine, monkeypatch):
        user = _make_user(crypto_address_ton="EQ_test")
        db = AsyncMock()
        # Already processed.
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=object()))

        response = _FakeAiohttpResponse(200, {
            "ok": True,
            "result": [{"transaction_id": {"hash": "tx-replay"}, "in_msg": {"value": str(int(5 * 1e9))}}],
        })
        session = _FakeAiohttpSession(response)

        extended = AsyncMock()
        monkeypatch.setattr(engine, "_extend_user_subscription", extended)

        await engine._check_ton_address(session, db, user)
        extended.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_non_200_response_is_ignored_without_raising(self, engine):
        user = _make_user(crypto_address_ton="EQ_test")
        db = AsyncMock()
        session = _FakeAiohttpSession(_FakeAiohttpResponse(500, {}))
        await engine._check_ton_address(session, db, user)  # must not raise


class TestCheckTrxAddress:
    @pytest.mark.asyncio
    async def test_credits_subscription_on_incoming_usdt_transfer(self, engine, monkeypatch):
        user = _make_user(crypto_address_trx="T_test_addr")
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))

        response = _FakeAiohttpResponse(200, {
            "data": [
                {"transaction_id": "tx-3", "to": "T_test_addr", "value": str(int(3 * 1e6))},  # 3 USDT
            ],
        })
        session = _FakeAiohttpSession(response)

        extended = AsyncMock()
        monkeypatch.setattr(engine, "_extend_user_subscription", extended)

        await engine._check_trx_address(session, db, user)
        extended.assert_awaited_once()
        assert extended.await_args.args[3] == pytest.approx(3.0)

    @pytest.mark.asyncio
    async def test_ignores_outgoing_transfer(self, engine, monkeypatch):
        """`to` must match the tracked address — a transfer *from* it
        (outgoing) must never be credited as a deposit."""
        user = _make_user(crypto_address_trx="T_test_addr")
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))

        response = _FakeAiohttpResponse(200, {
            "data": [{"transaction_id": "tx-4", "to": "someone-else", "value": str(int(5 * 1e6))}],
        })
        session = _FakeAiohttpSession(response)

        extended = AsyncMock()
        monkeypatch.setattr(engine, "_extend_user_subscription", extended)

        await engine._check_trx_address(session, db, user)
        extended.assert_not_awaited()


class TestExtendUserSubscription:
    @pytest.mark.asyncio
    async def test_extends_from_now_when_already_expired(self, engine):
        user = _make_user(expire_date=datetime.now(timezone.utc) - timedelta(days=5), data_limit_bytes=0)
        db = AsyncMock()
        db.add = MagicMock()  # real SQLAlchemy Session.add() is sync

        await engine._extend_user_subscription(db, user, "TON", 1.0, "tx-5")

        assert user.expire_date > datetime.now(timezone.utc) + timedelta(days=29)
        assert user.data_limit_bytes == 50 * 1024 * 1024 * 1024
        assert user.is_active is True
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_extends_from_existing_expiry_when_still_active(self, engine):
        future_expiry = datetime.now(timezone.utc) + timedelta(days=10)
        user = _make_user(expire_date=future_expiry, data_limit_bytes=1024)

        db = AsyncMock()
        db.add = MagicMock()
        await engine._extend_user_subscription(db, user, "TRX/USDT", 1.0, "tx-6")

        # 10 days remaining + 30 days credited, not reset to "now + 30".
        assert user.expire_date == pytest.approx(future_expiry + timedelta(days=30), abs=timedelta(seconds=5))

    @pytest.mark.asyncio
    async def test_db_error_triggers_rollback_not_raise(self, engine):
        user = _make_user()
        db = AsyncMock()
        db.add = MagicMock()
        db.commit.side_effect = RuntimeError("db exploded")

        await engine._extend_user_subscription(db, user, "TON", 1.0, "tx-7")  # must not raise
        db.rollback.assert_awaited_once()

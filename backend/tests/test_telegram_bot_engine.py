"""
MTGroup VPN Ultimate — Telegram Bot Engine Test Suite
Tests backend/app/telegram_bot.py's SingularityTelegramBot with the
python-telegram-bot Application and the DB session both mocked out — no
real bot token or network call.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.telegram_bot import SingularityTelegramBot


def _session_factory_with_config(value: dict | None):
    """Builds a db_session_factory whose `SELECT SystemConfig...` returns
    a row with `.value` set to json.dumps(value), or no row if value is None."""
    db = AsyncMock()
    if value is None:
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))
    else:
        row = SimpleNamespace(value=json.dumps(value))
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=row))

    class _Ctx:
        async def __aenter__(self):
            return db

        async def __aexit__(self, *exc):
            return False

    return lambda: _Ctx(), db


class TestStart:
    @pytest.mark.asyncio
    async def test_noop_when_no_system_config_row(self):
        factory, _ = _session_factory_with_config(None)
        bot = SingularityTelegramBot(session_factory=factory)
        await bot.start()
        assert bot.is_running is False
        assert bot.application is None

    @pytest.mark.asyncio
    async def test_noop_when_profile_disabled(self):
        factory, _ = _session_factory_with_config({"enabled": False})
        bot = SingularityTelegramBot(session_factory=factory)
        await bot.start()
        assert bot.is_running is False

    @pytest.mark.asyncio
    async def test_noop_when_bot_token_missing(self, monkeypatch):
        from backend.app.core.config import settings

        monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "")
        factory, _ = _session_factory_with_config({"enabled": True, "bot_token": ""})
        bot = SingularityTelegramBot(session_factory=factory)
        await bot.start()
        assert bot.is_running is False

    @pytest.mark.asyncio
    async def test_builds_and_starts_application_when_enabled(self, monkeypatch):
        factory, _ = _session_factory_with_config({"enabled": True, "bot_token": "123:ABC"})

        fake_app = MagicMock()
        fake_app.add_handler = MagicMock()
        fake_app.initialize = AsyncMock()
        fake_app.start = AsyncMock()
        fake_app.updater.start_polling = AsyncMock()

        fake_builder = MagicMock()
        fake_builder.token.return_value = fake_builder
        fake_builder.build.return_value = fake_app

        import backend.app.telegram_bot as tb_module
        monkeypatch.setattr(tb_module.Application, "builder", MagicMock(return_value=fake_builder))

        bot = SingularityTelegramBot(session_factory=factory)
        await bot.start()

        assert bot.is_running is True
        assert bot.application is fake_app
        fake_app.initialize.assert_awaited_once()
        fake_app.start.assert_awaited_once()
        fake_app.updater.start_polling.assert_awaited_once()
        assert fake_app.add_handler.call_count == 2  # /start and /status


class TestStop:
    @pytest.mark.asyncio
    async def test_noop_when_not_running(self):
        factory, _ = _session_factory_with_config(None)
        bot = SingularityTelegramBot(session_factory=factory)
        await bot.stop()  # must not raise
        assert bot.is_running is False

    @pytest.mark.asyncio
    async def test_shuts_down_running_application(self):
        factory, _ = _session_factory_with_config(None)
        bot = SingularityTelegramBot(session_factory=factory)
        bot.is_running = True
        bot.application = MagicMock()
        bot.application.updater.stop = AsyncMock()
        bot.application.stop = AsyncMock()
        bot.application.shutdown = AsyncMock()

        await bot.stop()

        bot.application.updater.stop.assert_awaited_once()
        bot.application.stop.assert_awaited_once()
        bot.application.shutdown.assert_awaited_once()
        assert bot.is_running is False


class TestSendAdminAlert:
    @pytest.mark.asyncio
    async def test_noop_when_not_running(self):
        factory, _ = _session_factory_with_config(None)
        bot = SingularityTelegramBot(session_factory=factory)
        await bot.send_admin_alert("test")  # must not raise, nothing to assert on

    @pytest.mark.asyncio
    async def test_sends_to_configured_admin_id(self):
        factory, _ = _session_factory_with_config({"admin_id": 999})
        bot = SingularityTelegramBot(session_factory=factory)
        bot.is_running = True
        bot.application = MagicMock()
        bot.application.bot.send_message = AsyncMock()

        await bot.send_admin_alert("intrusion detected")

        bot.application.bot.send_message.assert_awaited_once()
        _, kwargs = bot.application.bot.send_message.call_args
        assert kwargs["chat_id"] == 999
        assert "intrusion detected" in kwargs["text"]

    @pytest.mark.asyncio
    async def test_send_failure_is_caught_not_raised(self):
        factory, _ = _session_factory_with_config({"admin_id": 999})
        bot = SingularityTelegramBot(session_factory=factory)
        bot.is_running = True
        bot.application = MagicMock()
        bot.application.bot.send_message = AsyncMock(side_effect=RuntimeError("network down"))

        await bot.send_admin_alert("intrusion detected")  # must not raise

    @pytest.mark.asyncio
    async def test_noop_when_no_admin_id_configured(self):
        factory, _ = _session_factory_with_config({})
        bot = SingularityTelegramBot(session_factory=factory)
        bot.is_running = True
        bot.application = MagicMock()
        bot.application.bot.send_message = AsyncMock()

        await bot.send_admin_alert("test")

        bot.application.bot.send_message.assert_not_awaited()


class TestCmdStatus:
    @pytest.mark.asyncio
    async def test_unlinked_chat_id_gets_generic_reply(self):
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=None))

        class _Ctx:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *exc):
                return False

        bot = SingularityTelegramBot(session_factory=lambda: _Ctx())

        update = MagicMock()
        update.effective_chat.id = 12345
        update.message.reply_text = AsyncMock()

        await bot._cmd_status(update, context=MagicMock())

        update.message.reply_text.assert_awaited_once()
        assert "not linked" in update.message.reply_text.call_args.args[0]

    @pytest.mark.asyncio
    async def test_linked_user_gets_usage_summary(self):
        user = SimpleNamespace(
            username="alice", data_used_bytes=5 * 1024**3,
            data_limit_bytes=10 * 1024**3, expire_date=None,
        )
        db = AsyncMock()
        db.execute.return_value = MagicMock(scalar_one_or_none=MagicMock(return_value=user))

        class _Ctx:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *exc):
                return False

        bot = SingularityTelegramBot(session_factory=lambda: _Ctx())

        update = MagicMock()
        update.effective_chat.id = 12345
        update.message.reply_text = AsyncMock()

        await bot._cmd_status(update, context=MagicMock())

        text = update.message.reply_text.call_args.args[0]
        assert "alice" in text
        assert "5.00 GB" in text

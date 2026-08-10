"""
MTGroup VPN Ultimate — Telegram Bot Integration
Provides a fully automated bot for users to check subscription status,
and for admins to receive AI Threat Matrix alerts.
"""

import logging
import json
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from backend.app.core.config import settings
from backend.app.models import SystemConfig, User

try:
    from telegram import Update
    from telegram.ext import Application, CommandHandler, ContextTypes
    TELEGRAM_INSTALLED = True
except ImportError:
    TELEGRAM_INSTALLED = False

logger = logging.getLogger("mtgroup.telegram_bot")

class SingularityTelegramBot:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory
        self.application = None
        self.is_running = False

    async def start(self):
        if not TELEGRAM_INSTALLED:
            logger.warning("Telegram library not installed. Run `pip install python-telegram-bot`")
            return

        # Check if Telegram is enabled in DB config
        async with self.session_factory() as db:
            result = await db.execute(select(SystemConfig).where(SystemConfig.key == "telegram_profile"))
            cfg = result.scalar_one_or_none()
            if not cfg:
                return
            
            try:
                profile = json.loads(cfg.value)
            except Exception:
                profile = {}
                
            if not profile.get("enabled", False):
                return
                
            bot_token = profile.get("bot_token", settings.TELEGRAM_BOT_TOKEN)
            if not bot_token:
                logger.warning("Telegram Bot Token is missing in config.")
                return

        logger.info("🟢 Starting Telegram Bot Engine...")
        self.application = Application.builder().token(bot_token).build()

        self.application.add_handler(CommandHandler("start", self._cmd_start))
        self.application.add_handler(CommandHandler("status", self._cmd_status))

        await self.application.initialize()
        await self.application.start()
        await self.application.updater.start_polling()
        self.is_running = True
        logger.info("✅ Telegram Bot Engine listening for commands.")

    async def stop(self):
        if self.is_running and self.application:
            await self.application.updater.stop()
            await self.application.stop()
            await self.application.shutdown()
            self.is_running = False
            logger.info("🛑 Telegram Bot Engine stopped.")

    async def send_admin_alert(self, message: str):
        """Send a threat alert to the admin."""
        if not self.is_running or not self.application:
            return
            
        async with self.session_factory() as db:
            result = await db.execute(select(SystemConfig).where(SystemConfig.key == "telegram_profile"))
            cfg = result.scalar_one_or_none()
            if not cfg:
                return
            profile = json.loads(cfg.value)
            admin_id = profile.get("admin_id", settings.TELEGRAM_ADMIN_ID)
            
        if admin_id:
            try:
                await self.application.bot.send_message(chat_id=admin_id, text=f"🚨 <b>THREAT MATRIX ALERT</b>\n\n{message}", parse_mode="HTML")
            except Exception as e:
                logger.error(f"Failed to send Telegram alert: {e}")

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("Welcome to MTGroup VPN Ultimate. Use /status to check your subscription.")

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        chat_id = update.effective_chat.id
        async with self.session_factory() as db:
            result = await db.execute(select(User).where(User.telegram_chat_id == chat_id))
            user = result.scalar_one_or_none()
            
            if not user:
                await update.message.reply_text("Your Telegram ID is not linked to any subscription.")
                return
                
            used_gb = user.data_used_bytes / (1024**3)
            limit_gb = (user.data_limit_bytes / (1024**3)) if user.data_limit_bytes > 0 else "Unlimited"
            await update.message.reply_text(f"👤 <b>User:</b> {user.username}\n📊 <b>Usage:</b> {used_gb:.2f} GB / {limit_gb} GB\n⏳ <b>Expires:</b> {user.expire_date or 'Never'}", parse_mode="HTML")

# Singleton instance
# telegram_engine = SingularityTelegramBot(session_factory) # Instantiated in main.py

"""
MTGroup VPN Ultimate — Asynchronous Telegram Management & Alert Bot
═══════════════════════════════════════════════════════════════════
Provides Long-Polling bot interface for administrators and authorized 
agents. Includes zero-blocking HTTP helper functions for other modules 
(like orchestrator.py, loader.py, cli.py) to push alerts directly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

import httpx
from sqlalchemy import select

from backend.app.core.config import settings
from backend.app.models import Agent, LoginTracker, User, create_db_engine, create_session_factory

try:
    import psutil
except ImportError:
    psutil = None

try:
    from telegram import Update
    from telegram.ext import (
        ApplicationBuilder,
        CommandHandler,
        ContextTypes,
        MessageHandler,
        filters,
    )
except ImportError:
    pass  # Allow helpers to work even if telegram bot lib is missing

logger = logging.getLogger("mtgroup.telegram_bot")

# ---------------------------------------------------------------------------
# Independent HTTP Helper Functions (For external module usage)
# ---------------------------------------------------------------------------

async def push_telegram_message(message: str, chat_id: str | None = None) -> bool:
    """
    Pushes a raw text message to Telegram using httpx, completely bypassing 
    the bot long-polling process. Zero-blocking.
    Used by eBPF alerts, Node offline alerts, etc.
    """
    bot_token = settings.TELEGRAM_BOT_TOKEN
    target_chat = chat_id or os.getenv("TELEGRAM_ADMIN_ID")
    
    if not bot_token or not target_chat:
        logger.warning("Telegram Bot Token or Admin ID not set. Cannot push message.")
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": target_chat,
        "text": message,
        "parse_mode": "HTML"
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return True
    except Exception as e:
        logger.error("Failed to push Telegram message: %s", e)
        return False


async def push_telegram_document(file_path: str, caption: str = "", chat_id: str | None = None) -> bool:
    """
    Uploads a document (like a DB backup) directly to Telegram.
    Used by the `cli.py --cron backup-db` feature.
    """
    bot_token = settings.TELEGRAM_BOT_TOKEN
    target_chat = chat_id or os.getenv("TELEGRAM_ADMIN_ID")
    
    if not bot_token or not target_chat:
        return False

    if not os.path.exists(file_path):
        logger.error("File not found for Telegram upload: %s", file_path)
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            with open(file_path, "rb") as f:
                files = {"document": f}
                data = {"chat_id": target_chat, "caption": caption, "parse_mode": "HTML"}
                response = await client.post(url, data=data, files=files)
                response.raise_for_status()
                return True
    except Exception as e:
        logger.error("Failed to upload Telegram document: %s", e)
        return False


# ---------------------------------------------------------------------------
# Bot Handlers & Whitelist Security
# ---------------------------------------------------------------------------

class MTGroupBot:
    def __init__(self, engine=None, session_factory=None):
        # Accept external engine/session to share with FastAPI (prevents SQLite "database is locked")
        if engine and session_factory:
            self.engine = engine
            self.session_factory = session_factory
        else:
            self.engine = create_db_engine(settings.DATABASE_URL)
            self.session_factory = create_session_factory(self.engine)
        self.admin_id = str(os.getenv("TELEGRAM_ADMIN_ID", "")).strip()

    async def _is_authorized(self, user_id: int) -> bool:
        """White-list Security Check: Only Admin or DB-registered Agents."""
        user_str = str(user_id)
        if self.admin_id and user_str == self.admin_id:
            return True
        
        # Check Agent table
        try:
            async with self.session_factory() as session:
                result = await session.execute(
                    select(Agent).where(Agent.telegram_id == user_str)
                )
                agent = result.scalar_one_or_none()
                return agent is not None
        except Exception as e:
            logger.error("Error verifying authorization: %s", e)
            return False

    async def auth_middleware(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
        """Middleware to block unauthorized access silently."""
        if not update.effective_user:
            return False
            
        user_id = update.effective_user.id
        if not await self._is_authorized(user_id):
            logger.warning("UNAUTHORIZED Telegram Access Attempt from ID: %s", user_id)
            # Siber sızıntıyı önlemek için kesinlikle cevap verme
            return False
        return True

    # ── Command: /status ──────────────────────────────────────────────

    async def cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Reports Live CPU/RAM and eBPF kernel stats."""
        if not await self.auth_middleware(update, context):
            return

        # Run psutil in thread to avoid blocking the async event loop (cpu_percent sleeps 100ms)
        if psutil:
            cpu = await asyncio.get_event_loop().run_in_executor(None, psutil.cpu_percent, 0.1)
            mem = psutil.virtual_memory()
            mem_percent = mem.percent
        else:
            cpu = 0.0
            mem_percent = 0.0

        ebpf_stats = {"total_dropped": 0, "active_v4": 0, "active_v6": 0}
        try:
            # /run (not /tmp) — root-only-writable on most distros, so a
            # local unprivileged user can't plant/symlink this file to
            # feed fake stats into the bot.
            with open("/run/mtgroup/xdp_stats.json", "r") as f:
                ebpf_stats = json.load(f)
        except Exception:
            pass

        msg = (
            "🟢 <b>MTGroup Ultimate System Status</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"💻 <b>CPU:</b> {cpu}%\n"
            f"🧠 <b>RAM:</b> {mem_percent}%\n\n"
            "🛡️ <b>eBPF Kernel Firewall</b>\n"
            f"   ├ Dropped Packets: <code>{ebpf_stats['total_dropped']}</code>\n"
            f"   ├ Active V4 Bans: <code>{ebpf_stats['active_v4']}</code>\n"
            f"   └ Active V6 Bans: <code>{ebpf_stats['active_v6']}</code>\n"
        )
        
        await update.message.reply_html(msg)

    # ── Command: /user ────────────────────────────────────────────────

    async def cmd_user(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Reports specific user's quota and last seen, decrypting RAM data via crypto_quantum."""
        if not await self.auth_middleware(update, context):
            return

        if not context.args:
            await update.message.reply_text("Usage: /user <username>")
            return

        target_username = context.args[0]

        try:
            async with self.session_factory() as session:
                # Find User
                result = await session.execute(
                    select(User).where(User.username == target_username)
                )
                user = result.scalar_one_or_none()
                
                if not user:
                    await update.message.reply_text(f"User '{target_username}' not found.")
                    return

                # Find Last Login (crypto_quantum auto-decrypts 'source_ip' etc if accessed, 
                # but we just need time and result here)
                log_result = await session.execute(
                    select(LoginTracker)
                    .where(LoginTracker.username == target_username)
                    .order_by(LoginTracker.attempted_at.desc())
                    .limit(1)
                )
                last_login = log_result.scalar_one_or_none()

                quota_str = f"{user.quota_bytes / (1024**3):.2f} GB" if user.quota_bytes else "Unlimited"
                used_str = f"{(user.used_traffic_down + user.used_traffic_up) / (1024**3):.2f} GB"
                status_icon = "🟢" if user.is_active else "🔴"
                
                last_seen_str = "Never"
                if last_login:
                    last_seen_str = last_login.attempted_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                    if last_login.source_ip:
                        # source_ip is automatically decrypted by SQLAlchemy EncryptedType in models.py
                        last_seen_str += f" (IP: {last_login.source_ip})"

                msg = (
                    f"{status_icon} <b>User Info:</b> <code>{user.username}</code>\n"
                    "━━━━━━━━━━━━━━━━━━━━\n"
                    f"📊 <b>Quota:</b> {used_str} / {quota_str}\n"
                    f"📅 <b>Expires:</b> {user.expires_at.strftime('%Y-%m-%d') if user.expires_at else 'Never'}\n"
                    f"👁️ <b>Last Seen:</b> {last_seen_str}\n"
                )

                await update.message.reply_html(msg)

        except Exception as e:
            logger.error("Error executing /user: %s", e)
            await update.message.reply_text("Internal error occurred while fetching user data.")

    # ── Unknown Handler ──────────────────────────────────────────────

    async def handle_unknown(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Silently ignore unknown commands from authorized users."""
        if await self.auth_middleware(update, context):
            await update.message.reply_text("Unknown command. Try /status or /user <username>")


# ---------------------------------------------------------------------------
# Bot Entry Point
# ---------------------------------------------------------------------------

def run_bot() -> None:
    """Initializes and runs the Telegram Bot in Long-Polling Mode."""
    token = settings.TELEGRAM_BOT_TOKEN
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN is missing. Bot cannot start.")
        return

    logger.info("Initializing MTGroup Telegram Bot...")
    bot_app = MTGroupBot()
    
    app = ApplicationBuilder().token(token).build()

    app.add_handler(CommandHandler("status", bot_app.cmd_status))
    app.add_handler(CommandHandler("durum", bot_app.cmd_status))
    app.add_handler(CommandHandler("user", bot_app.cmd_user))
    app.add_handler(MessageHandler(filters.COMMAND, bot_app.handle_unknown))

    logger.info("Bot is running in Long-Polling mode...")
    app.run_polling()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_bot()

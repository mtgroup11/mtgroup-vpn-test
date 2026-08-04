"""
MTGroup VPN Ultimate — Telegram Bot C2
Enterprise-grade async Telegram bot with Interactive UI
"""

from __future__ import annotations
import asyncio
import logging
from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters
)

from utils.config import BOT_TOKEN, ADMIN_ID, logger
from utils.api_client import api
from utils.keyboards import get_main_menu

# Import handlers
from handlers.user import user_callback_handler
from handlers.admin import (
    admin_callback_handler, 
    is_admin,
    BROADCAST_MSG, broadcast_start, broadcast_receive, broadcast_cancel
)
from handlers.reseller import (
    reseller_callback_handler,
    ADD_CUST_USERNAME, ADD_CUST_PASSWORD, ADD_CUST_DATA,
    add_cust_start, add_cust_username, add_cust_password, add_cust_data
)

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command - Show Main Menu."""
    user_id = update.effective_user.id
    admin = is_admin(user_id)
    # Mock reseller check (normally via DB)
    reseller = False 
    
    welcome = (
        "🛡️ *MTGroup VPN Ultimate*\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Welcome to the ultimate VPN dashboard. Please use the interactive menu below."
    )
    
    await update.message.reply_text(
        welcome, 
        parse_mode="Markdown",
        reply_markup=get_main_menu(is_admin=admin, is_reseller=reseller)
    )

async def main_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Delegate callbacks to specific handlers."""
    query = update.callback_query
    
    if query.data == "main_menu":
        await query.answer()
        await cmd_start(update, context)
        return
        
    # Try delegating to module handlers
    if await user_callback_handler(update, context):
        return
    if await admin_callback_handler(update, context):
        return
    if await reseller_callback_handler(update, context):
        return
        
    # Handle conversation start callbacks
    if query.data == "admin_broadcast":
        # Conversation handled by ConversationHandler, this is just a fallback log
        pass
    if query.data == "reseller_add":
        pass
        
    await query.answer("Not implemented yet.", show_alert=True)

async def telemetry_monitor(app: Application) -> None:
    """Background task that monitors system health."""
    while True:
        try:
            await asyncio.sleep(300)
            if not ADMIN_ID: continue
            
            stats = await api.get("/api/system/stats")
            if stats:
                alerts = []
                if stats["cpu_percent"] > 90: alerts.append(f"🔴 CPU at {stats['cpu_percent']:.0f}%")
                if stats["memory_percent"] > 90: alerts.append(f"🔴 RAM at {stats['memory_percent']:.0f}%")
                
                if alerts:
                    msg = "⚠️ *System Alert*\n━━━━━━━━━━━━━━━━━━━━━\n" + "\n".join(alerts)
                    await app.bot.send_message(ADMIN_ID, msg, parse_mode="Markdown")
                    
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Telemetry monitor error: {e}")
            await asyncio.sleep(60)

def create_bot_application() -> Application:
    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set!")
        raise ValueError("TELEGRAM_BOT_TOKEN environment variable is required")

    app = Application.builder().token(BOT_TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("menu", cmd_start))
    
    # Broadcast Conversation Handler
    broadcast_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(broadcast_start, pattern="^admin_broadcast$")],
        states={
            BROADCAST_MSG: [MessageHandler(filters.TEXT & ~filters.COMMAND, broadcast_receive)]
        },
        fallbacks=[CommandHandler("cancel", broadcast_cancel)]
    )
    app.add_handler(broadcast_conv)
    
    # Add Customer Conversation Handler
    add_cust_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(add_cust_start, pattern="^reseller_add$")],
        states={
            ADD_CUST_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_cust_username)],
            ADD_CUST_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_cust_password)],
            ADD_CUST_DATA: [MessageHandler(filters.TEXT & ~filters.COMMAND, add_cust_data)]
        },
        fallbacks=[CommandHandler("cancel", broadcast_cancel)] # reuse cancel
    )
    app.add_handler(add_cust_conv)

    # General callback router
    app.add_handler(CallbackQueryHandler(main_callback_handler))

    return app

async def run_bot() -> None:
    await api.authenticate()
    app = create_bot_application()
    monitor_task = asyncio.create_task(telemetry_monitor(app))
    
    logging.info("🤖 MTGroup Telegram Bot started in Enterprise Mode")
    
    try:
        await app.initialize()
        await app.start()
        await app.updater.start_polling(drop_pending_updates=True)
        
        stop_event = asyncio.Event()
        await stop_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        monitor_task.cancel()
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        await api.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s")
    asyncio.run(run_bot())

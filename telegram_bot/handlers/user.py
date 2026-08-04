import io
import qrcode
from telegram import Update, InputFile
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from ..utils.api_client import api
from ..utils.keyboards import get_main_menu

async def send_user_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send the user's status with usage bar."""
    chat_id = update.effective_user.id
    
    # Try editing existing message first (if from callback), else reply
    message = update.callback_query.message if update.callback_query else update.message
    
    users_data = await api.get("/api/users?per_page=100")
    if not users_data:
        await message.reply_text("❌ Could not connect to server.")
        return

    user = next((u for u in users_data.get("users", []) if u.get("telegram_chat_id") == chat_id), None)

    if not user:
        await message.reply_text("❓ Your Telegram account is not linked to any VPN user.\nAsk your admin to link your Telegram ID.")
        return

    data_used_gb = user["data_used_bytes"] / (1024 ** 3)
    data_limit_gb = user["data_limit_bytes"] / (1024 ** 3) if user["data_limit_bytes"] > 0 else 0

    status = "🟢 Active" if user["is_active"] else "🔴 Suspended"
    expire_str = user.get("expire_date", "♾️ Unlimited")
    if isinstance(expire_str, str) and len(expire_str) > 10:
        expire_str = expire_str[:10]

    if data_limit_gb > 0:
        pct = min(100, data_used_gb / data_limit_gb * 100)
        filled = int(20 * pct / 100)
        bar = "█" * filled + "░" * (20 - filled)
        usage_str = f"`[{bar}]` {pct:.0f}%"
    else:
        usage_str = "♾️ Unlimited"

    msg = (
        f"👤 *Your VPN Status*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📛 Username: `{user['username']}`\n"
        f"📶 Status: {status}\n"
        f"📊 Data: {data_used_gb:.2f}/{data_limit_gb:.0f} GB\n"
        f"📈 Usage: {usage_str}\n"
        f"📅 Expires: {expire_str}\n"
    )

    await message.reply_text(
        msg, 
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=get_main_menu()
    )


async def send_user_subscription(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send subscription link along with a QR code."""
    chat_id = update.effective_user.id
    message = update.callback_query.message if update.callback_query else update.message
    
    users_data = await api.get("/api/users?per_page=100")
    if not users_data:
        await message.reply_text("❌ Could not connect to server.")
        return

    user = next((u for u in users_data.get("users", []) if u.get("telegram_chat_id") == chat_id), None)

    if not user:
        await message.reply_text("❓ Your account is not linked.")
        return

    sub_url = user.get("subscription_url")
    if not sub_url:
        await message.reply_text("❌ No subscription URL available for your account.")
        return

    # Generate QR Code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(sub_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    bio = io.BytesIO()
    img.save(bio, "PNG")
    bio.seek(0)

    caption = (
        f"🔗 *Your Subscription Link:*\n\n`{sub_url}`\n\n"
        f"📱 *Scan the QR code* with your camera or copy the link to import into V2Box, Streisand, or v2rayNG."
    )
    
    await message.reply_photo(
        photo=InputFile(bio, filename="subscription_qr.png"),
        caption=caption,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=get_main_menu()
    )

async def user_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Handle user-specific callbacks. Returns True if handled."""
    query = update.callback_query
    data = query.data
    
    if data == "user_status":
        await query.answer()
        await send_user_status(update, context)
        return True
    elif data == "user_refresh_sub":
        await query.answer()
        await send_user_subscription(update, context)
        return True
        
    return False

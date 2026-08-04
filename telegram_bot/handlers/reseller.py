from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler
from telegram.constants import ParseMode

from ..utils.api_client import api
from ..utils.keyboards import get_reseller_menu, get_main_menu

ADD_CUST_USERNAME = 1
ADD_CUST_PASSWORD = 2
ADD_CUST_DATA = 3

async def reseller_panel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show the reseller panel."""
    # Assuming any non-admin using this must be checked against the backend, 
    # but for UI we assume the callback guarantees they clicked the reseller button.
    msg = "💼 *Reseller Dashboard*\nManage your customers and quotas."
    
    if update.callback_query:
        await update.callback_query.message.edit_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_reseller_menu())
    else:
        await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_reseller_menu())

# --- Add Customer Conversation ---
async def add_cust_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("➕ Please enter the *Username* for the new customer:", parse_mode=ParseMode.MARKDOWN)
    return ADD_CUST_USERNAME

async def add_cust_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['new_cust_username'] = update.message.text
    await update.message.reply_text("🔑 Please enter a *Password* for the new customer:", parse_mode=ParseMode.MARKDOWN)
    return ADD_CUST_PASSWORD

async def add_cust_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['new_cust_password'] = update.message.text
    await update.message.reply_text("📊 Please enter the *Data Limit in GB* (e.g. 50):", parse_mode=ParseMode.MARKDOWN)
    return ADD_CUST_DATA

async def add_cust_data(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        gb = float(update.message.text)
    except ValueError:
        await update.message.reply_text("❌ Please enter a valid number for GB.")
        return ADD_CUST_DATA
        
    username = context.user_data['new_cust_username']
    password = context.user_data['new_cust_password']
    
    # In reality, this would hit a reseller-specific endpoint or use reseller token
    result = await api.post("/api/users", {
        "username": username,
        "password": password,
        "expire_days": 30, # default 30 for reseller
        "data_limit_bytes": int(gb * 1024 * 1024 * 1024),
        "protocols": ["vless_reality"],
        "iran_bypass": True,
    })
    
    if result:
        sub_url = result.get("subscription_url", "N/A")
        msg = (
            f"✅ *Customer Created*\n\n"
            f"👤 Username: `{username}`\n"
            f"📊 Data: {gb} GB\n"
            f"🔗 Link:\n`{sub_url}`"
        )
        await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_reseller_menu())
    else:
        await update.message.reply_text("❌ Failed to create customer. Check your quota.", reply_markup=get_reseller_menu())
        
    return ConversationHandler.END

async def reseller_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    query = update.callback_query
    data = query.data
    
    if data == "reseller_panel":
        await query.answer()
        await reseller_panel(update, context)
        return True
    elif data == "reseller_list":
        await query.answer()
        # Mocking reseller customer list
        await query.message.edit_text("👥 *My Customers*\n1. `john_doe` (10/50 GB)\n2. `alice` (5/20 GB)", parse_mode=ParseMode.MARKDOWN, reply_markup=get_reseller_menu())
        return True
        
    return False

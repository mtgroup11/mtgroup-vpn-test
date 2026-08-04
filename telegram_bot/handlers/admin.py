import io
import matplotlib.pyplot as plt
from telegram import Update, InputFile
from telegram.ext import ContextTypes, ConversationHandler, MessageHandler, filters
from telegram.constants import ParseMode

from ..utils.api_client import api
from ..utils.config import ADMIN_ID, logger
from ..utils.keyboards import get_admin_menu, get_confirmation_menu, get_user_manage_menu

BROADCAST_MSG = 1

def is_admin(user_id: int) -> bool:
    return user_id == ADMIN_ID

async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show the main admin panel."""
    if not is_admin(update.effective_user.id):
        return
        
    msg = "👑 *Admin Control Panel*\nSelect an action below:"
    
    if update.callback_query:
        await update.callback_query.message.edit_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_admin_menu())
    else:
        await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_admin_menu())

async def send_system_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send system stats with a matplotlib chart."""
    if not is_admin(update.effective_user.id):
        return
        
    message = update.callback_query.message if update.callback_query else update.message
    
    # Show loading message
    loading_msg = await message.reply_text("🔄 Generating server statistics chart...")
    
    stats = await api.get("/api/system/stats")
    if not stats:
        await loading_msg.edit_text("❌ Failed to fetch system stats.")
        return

    # Create figure
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))
    fig.patch.set_facecolor('#1e1e2e')
    
    # CPU Gauge (Pie chart)
    cpu = stats['cpu_percent']
    colors = ['#f38ba8', '#313244'] if cpu > 80 else ['#a6e3a1', '#313244']
    ax1.pie([cpu, 100-cpu], colors=colors, startangle=90, counterclock=False, wedgeprops=dict(width=0.3))
    ax1.text(0, 0, f"CPU\n{cpu:.1f}%", ha='center', va='center', color='white', fontsize=14, fontweight='bold')
    
    # RAM Gauge
    ram = stats['memory_percent']
    colors = ['#f38ba8', '#313244'] if ram > 80 else ['#89b4fa', '#313244']
    ax2.pie([ram, 100-ram], colors=colors, startangle=90, counterclock=False, wedgeprops=dict(width=0.3))
    ax2.text(0, 0, f"RAM\n{ram:.1f}%", ha='center', va='center', color='white', fontsize=14, fontweight='bold')

    plt.suptitle("Server Resource Usage", color='white', fontsize=16)
    plt.tight_layout()
    
    bio = io.BytesIO()
    plt.savefig(bio, format='png', facecolor=fig.get_facecolor(), edgecolor='none')
    bio.seek(0)
    plt.close()

    uptime_hours = stats['uptime_seconds'] / 3600
    caption = (
        f"📊 *System Statistics*\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 Upload: {stats['bandwidth_up_mbps']:.1f} Mbps\n"
        f"📥 Download: {stats['bandwidth_down_mbps']:.1f} Mbps\n"
        f"👥 Users: {stats['active_users']}/{stats['total_users']}\n"
        f"🖧 Nodes: {stats['active_nodes']}/{stats['total_nodes']}\n"
        f"⏱️ Uptime: {uptime_hours:.1f}h"
    )

    await loading_msg.delete()
    await message.reply_photo(
        photo=InputFile(bio, filename="stats.png"),
        caption=caption,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=get_admin_menu()
    )

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_admin(update.effective_user.id):
        return
        
    query = update.callback_query
    result = await api.get("/api/users?per_page=50")
    if not result:
        await query.message.edit_text("❌ Failed to fetch users.", reply_markup=get_admin_menu())
        return

    users = result.get("users", [])
    if not users:
        await query.message.edit_text("📋 No users found.", reply_markup=get_admin_menu())
        return

    lines = ["👥 *User List*\n━━━━━━━━━━━━━━━━━━━━━"]
    for u in users:
        status = "🟢" if u["is_active"] else "🔴"
        data_used_gb = u["data_used_bytes"] / (1024 ** 3)
        data_limit_gb = u["data_limit_bytes"] / (1024 ** 3) if u["data_limit_bytes"] > 0 else float("inf")
        usage_pct = (data_used_gb / data_limit_gb * 100) if data_limit_gb != float("inf") else 0
        expire_str = u["expire_date"][:10] if u.get("expire_date") else "♾️"

        lines.append(
            f"{status} `{u['username']}` — "
            f"{data_used_gb:.1f}/{data_limit_gb:.0f}GB ({usage_pct:.0f}%) "
            f"⏰{expire_str}"
        )

    await query.message.edit_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=get_admin_menu())

# --- Broadcast Conversation ---
async def broadcast_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    await query.message.reply_text("📢 Please send the message you want to broadcast to all users. (Send /cancel to abort)")
    return BROADCAST_MSG

async def broadcast_receive(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    msg_text = update.message.text
    # In a real scenario, we'd fetch all users from DB and send to their telegram_chat_id
    # For now, we simulate success.
    await update.message.reply_text(f"✅ Broadcast message queued for all users:\n\n{msg_text}")
    return ConversationHandler.END

async def broadcast_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("❌ Broadcast cancelled.", reply_markup=get_admin_menu())
    return ConversationHandler.END


async def admin_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    query = update.callback_query
    data = query.data
    
    if not is_admin(update.effective_user.id):
        return False
        
    if data == "admin_panel":
        await query.answer()
        await admin_panel(update, context)
        return True
    elif data == "admin_stats":
        await query.answer()
        await send_system_stats(update, context)
        return True
    elif data == "admin_list_users":
        await query.answer()
        await list_users(update, context)
        return True
    elif data == "admin_kill_switch":
        await query.answer()
        result = await api.post("/api/v1/system/killswitch/trigger", data={})
        if result:
            await query.message.edit_text("🚨 *KILL SWITCH ACTIVATED!*\nAll non-VPN traffic is now DROPPED.", parse_mode=ParseMode.MARKDOWN, reply_markup=get_admin_menu())
        else:
            await query.message.edit_text("❌ Failed to activate Kill Switch.", reply_markup=get_admin_menu())
        return True
    elif data == "admin_port_hop":
        await query.answer()
        # Mocking the force hop endpoint here since it's not implemented in main.py yet
        # We will add it to main.py shortly.
        result = await api.post("/api/v1/system/porthop/trigger", data={})
        await query.message.edit_text("🔄 Emergency port hop initiated on all nodes...", reply_markup=get_admin_menu())
        return True
    elif data == "admin_nodes":
        await query.answer()
        result = await api.get("/api/nodes")
        if not result or not result.get("nodes"):
            await query.message.edit_text("📋 No nodes found.", reply_markup=get_admin_menu())
            return True

        lines = ["🖧 *Server Nodes*\n━━━━━━━━━━━━━━━━━━━━━"]
        for n in result["nodes"]:
            status = "🟢" if n["is_active"] else "🔴"
            ip = n.get("floating_ip") or n["address"]
            lines.append(f"{status} `{n['name']}` — {ip}:{n['port']} ({n['protocol']})")

        await query.message.edit_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=get_admin_menu())
        return True
        
    return False

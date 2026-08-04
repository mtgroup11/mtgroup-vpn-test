from telegram import InlineKeyboardButton, InlineKeyboardMarkup

def get_main_menu(is_admin: bool = False, is_reseller: bool = False) -> InlineKeyboardMarkup:
    """Main dashboard menu."""
    keyboard = [
        [InlineKeyboardButton("👤 My Status", callback_data="user_status")],
        [InlineKeyboardButton("🔗 Refresh Subscription", callback_data="user_refresh_sub")]
    ]
    
    if is_admin:
        keyboard.append([InlineKeyboardButton("👑 Admin Panel", callback_data="admin_panel")])
    elif is_reseller:
        keyboard.append([InlineKeyboardButton("💼 Reseller Panel", callback_data="reseller_panel")])
        
    return InlineKeyboardMarkup(keyboard)

def get_admin_menu() -> InlineKeyboardMarkup:
    """Admin dashboard."""
    keyboard = [
        [
            InlineKeyboardButton("➕ Create User", callback_data="admin_create_user"),
            InlineKeyboardButton("👥 List Users", callback_data="admin_list_users")
        ],
        [
            InlineKeyboardButton("📊 System Stats", callback_data="admin_stats"),
            InlineKeyboardButton("🖧 Nodes", callback_data="admin_nodes")
        ],
        [
            InlineKeyboardButton("🔴 KILL SWITCH", callback_data="admin_kill_switch"),
            InlineKeyboardButton("🔄 FORCE HOP", callback_data="admin_port_hop")
        ],
        [InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_reseller_menu() -> InlineKeyboardMarkup:
    """Reseller dashboard."""
    keyboard = [
        [
            InlineKeyboardButton("➕ Add Customer", callback_data="reseller_add"),
            InlineKeyboardButton("👥 My Customers", callback_data="reseller_list")
        ],
        [InlineKeyboardButton("🔙 Back to Main", callback_data="main_menu")]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_cancel_menu() -> InlineKeyboardMarkup:
    """Simple cancel button for conversation states."""
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_action")]]
    return InlineKeyboardMarkup(keyboard)

def get_confirmation_menu(action: str, payload: str) -> InlineKeyboardMarkup:
    """Generic confirmation menu."""
    keyboard = [
        [
            InlineKeyboardButton("✅ Confirm", callback_data=f"confirm_{action}_{payload}"),
            InlineKeyboardButton("❌ Cancel", callback_data="cancel_action")
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_user_manage_menu(user_id: int) -> InlineKeyboardMarkup:
    """Manage a specific user."""
    keyboard = [
        [
            InlineKeyboardButton("⏸ Suspend", callback_data=f"user_suspend_{user_id}"),
            InlineKeyboardButton("🗑 Delete", callback_data=f"user_delete_{user_id}")
        ],
        [InlineKeyboardButton("🔙 Back", callback_data="admin_list_users")]
    ]
    return InlineKeyboardMarkup(keyboard)

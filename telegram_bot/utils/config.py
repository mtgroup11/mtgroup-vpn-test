import os
import logging

logger = logging.getLogger("mtgroup.telegram")

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
ADMIN_ID = int(os.getenv("TELEGRAM_ADMIN_ID", "0"))
API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8443")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "MTGroup@2024!Secure")

# Supported languages
LANGUAGES = {
    "en": "English 🇬🇧",
    "tr": "Türkçe 🇹🇷",
    "ru": "Русский 🇷🇺",
    "fa": "فارسی 🇮🇷",
}

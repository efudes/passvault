#!/usr/bin/env python3
"""PassVault Telegram bot.

Single purpose: give users a button that opens the PassVault Mini App at
https://<DOMAIN>/app/. The bot handles NO passwords and NO secrets — it never
asks for, receives, stores, or logs the master password or any vault data. All
crypto happens inside the Mini App (zero-knowledge), exactly as in the browser
extension. The user logs in inside the Mini App with email + master password.

Config comes from the environment (the same $APP_DIR/.env as the backend):
  TELEGRAM_BOT_TOKEN   required — token from @BotFather
  DOMAIN               the HTTPS host serving the Mini App (required)

Run locally:   TELEGRAM_BOT_TOKEN=... DOMAIN=... python bot.py
On the VPS:    via deploy/passvault-bot.service (installed by setup.sh when a
               token is present).
"""
import logging
import os

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    MenuButtonWebApp,
    Update,
    WebAppInfo,
)
from telegram.ext import Application, CommandHandler, ContextTypes

DOMAIN = os.environ.get("DOMAIN", "").strip()
if not DOMAIN:
    raise RuntimeError("DOMAIN env variable is required")
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
APP_URL = f"https://{DOMAIN}/app/"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
# httpx/telegram log request URLs at INFO, which leaks the bot token into
# journald (e.g. ".../bot<TOKEN>/getMe"). The token is a Telegram API
# credential, not a vault secret, but keep it out of logs anyway.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)
log = logging.getLogger("passvault.bot")

_WELCOME = (
    "PassVault — ваш личный менеджер паролей.\n\n"
    "Нажмите кнопку ниже, чтобы открыть хранилище. Мастер-пароль вводится "
    "только внутри приложения, шифрование происходит на вашем устройстве — "
    "бот никогда не получает ни пароль, ни данные хранилища."
)


def _open_vault_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("Открыть хранилище", web_app=WebAppInfo(url=APP_URL))]]
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.message:
        await update.message.reply_text(_WELCOME, reply_markup=_open_vault_keyboard())


async def _post_init(app: Application) -> None:
    # Persistent chat menu button (the "≡" next to the input box) opens the
    # Mini App for everyone, so users don't need to type /start each time.
    await app.bot.set_chat_menu_button(
        menu_button=MenuButtonWebApp(text="Хранилище", web_app=WebAppInfo(url=APP_URL))
    )
    log.info("menu button set; app_url=%s", APP_URL)


def main() -> None:
    if not TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN not set — nothing to run.")
    app = Application.builder().token(TOKEN).post_init(_post_init).build()
    app.add_handler(CommandHandler("start", start))
    log.info("PassVault bot starting (long polling); app_url=%s", APP_URL)
    # Only need message updates for /start; this also avoids pulling anything else.
    app.run_polling(allowed_updates=["message"])


if __name__ == "__main__":
    main()

"""Runtime configuration, read from environment.

Strong secrets are read from env. If a required secret is missing we generate a
random ephemeral one for local dev and warn loudly — those secrets do NOT persist
across restarts (JWTs and prelogin fake-salts will change), so production MUST set
them explicitly (see deploy/.env.example).
"""
import logging
import os
import secrets

log = logging.getLogger("passvault.config")


def _secret(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        value = secrets.token_urlsafe(48)
        log.warning(
            "%s not set — generated an EPHEMERAL dev secret. "
            "Set it in the environment for production.",
            name,
        )
    return value


JWT_SECRET = _secret("JWT_SECRET")
SERVER_HMAC_SECRET = _secret("SERVER_HMAC_SECRET")

# JWT lifetime. The real secret (vaultKey) is wiped client-side on auto-lock
# regardless of this TTL — see spec section 5 / vault-web auto-lock.
JWT_TTL_HOURS = int(os.environ.get("JWT_TTL_HOURS", "12"))

# CORS allow-list. Comma-separated origins. Empty in dev means "no cross-origin"
# but local same-origin tooling/curl still works.
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()
]

DB_PATH = os.environ.get("PASSVAULT_DB", "passvault.db")

# Telegram bot token — only used by the (later) /api/tg/verify endpoint. Optional
# for the backend to boot.
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")

RATE_LIMIT_AUTH = os.environ.get("RATE_LIMIT_AUTH", "10/minute")

# Must mirror crypto/crypto.js KDF_PARAMS. Returned for UNKNOWN emails on
# prelogin so responses are indistinguishable from real accounts.
DEFAULT_KDF_PARAMS = {
    "type": "argon2id",
    "mem": 65536,
    "time": 3,
    "parallelism": 1,
    "hashLen": 32,
}

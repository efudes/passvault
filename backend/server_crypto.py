"""Server-side crypto helpers.

This file intentionally does NOT touch any zero-knowledge secret. It only:
  - hashes the client-supplied authHash again at rest (argon2id), and
  - derives a deterministic fake salt for unknown emails so that known vs.
    unknown accounts are indistinguishable to an attacker.
"""
import base64
import hashlib
import hmac
import time
from typing import Optional
from urllib.parse import parse_qsl

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

import config

# Argon2id hashing of the (already high-entropy, 32-byte) client authHash at rest.
# Default argon2-cffi params are appropriate here; the input is not a low-entropy
# human password.
_ph = PasswordHasher()

# A precomputed hash used to equalize timing when an email is unknown, so login
# does roughly the same work whether or not the account exists.
_DUMMY_HASH = _ph.hash("dummy-timing-equalizer")


def hash_auth(auth_hash_b64: str) -> str:
    return _ph.hash(auth_hash_b64)


def verify_auth(stored_hash: str, auth_hash_b64: str) -> bool:
    try:
        _ph.verify(stored_hash, auth_hash_b64)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False


def dummy_verify() -> None:
    """Burn comparable CPU time for unknown-account logins (anti-enumeration)."""
    try:
        _ph.verify(_DUMMY_HASH, "definitely-wrong")
    except (VerifyMismatchError, InvalidHashError):
        pass


def fake_salt(email: str) -> str:
    """Deterministic per-email fake salt = base64(HMAC-SHA256(secret, email)[:16]).

    Returned for unknown emails on prelogin so responses are indistinguishable
    from real accounts.
    """
    mac = hmac.new(
        config.SERVER_HMAC_SECRET.encode("utf-8"),
        email.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).digest()[:16]
    return base64.b64encode(mac).decode("ascii")


def fake_recovery(email: str) -> dict:
    """Deterministic fake recovery bundle for unknown emails (anti-enumeration).

    /api/recover/prelogin must return the same SHAPE of response whether or not
    the account exists, so an attacker can't enumerate accounts. The fake is
    derived from SERVER_HMAC_SECRET + email, so it's stable across calls and
    indistinguishable from a real bundle — but useless: it decrypts to nothing
    without a matching recovery code (which only the real user has).

    Real `recoveryProtectedVaultKey` = base64(12-byte IV ‖ 32-byte key ‖ 16-byte
    GCM tag) = 60 bytes, so we emit 60 deterministic bytes to match.
    """
    base = email.strip().lower().encode("utf-8")
    secret = config.SERVER_HMAC_SECRET.encode("utf-8")
    salt = hmac.new(secret, b"recovery-salt:" + base, hashlib.sha256).digest()[:16]
    blob = b""
    counter = 0
    while len(blob) < 60:
        blob += hmac.new(
            secret, b"recovery-blob:%d:" % counter + base, hashlib.sha256
        ).digest()
        counter += 1
    return {
        "recoverySalt": base64.b64encode(salt).decode("ascii"),
        "recoveryProtectedVaultKey": base64.b64encode(blob[:60]).decode("ascii"),
    }


def verify_telegram_init_data(
    init_data: str, bot_token: str, max_age_seconds: int = 86400
) -> Optional[dict]:
    """Validate a Telegram Mini App `initData` string against the bot token.

    Implements Telegram's documented HMAC scheme:
        secret_key = HMAC_SHA256(key="WebAppData", msg=bot_token)
        expected   = hex(HMAC_SHA256(key=secret_key, msg=data_check_string))
    where data_check_string is the remaining fields (minus `hash`) sorted by key
    and joined with '\\n' as "key=value".

    Returns the parsed fields on success, or None on any failure. This is a
    convenience / anti-embedding check ONLY — never the zero-knowledge auth
    boundary. The result (and `initData`, which contains user info) must not be
    logged.
    """
    if not bot_token or not init_data:
        return None
    fields = dict(parse_qsl(init_data, keep_blank_values=True))
    received = fields.pop("hash", None)
    if not received:
        return None
    check_string = "\n".join(f"{k}={fields[k]}" for k in sorted(fields))
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    expected = hmac.new(
        secret_key, check_string.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, received):
        return None
    # Optional freshness check to limit replay of a captured launch.
    if max_age_seconds:
        auth_date = fields.get("auth_date")
        try:
            if auth_date and (time.time() - int(auth_date)) > max_age_seconds:
                return None
        except ValueError:
            return None
    return fields

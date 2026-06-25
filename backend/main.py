"""PassVault backend — FastAPI app (milestone M2: register/prelogin/login/vault).

The client does ALL crypto and sends only ciphertext + hashes. This server never
receives, logs, or stores the master password, master key, vault key, or any
plaintext vault item.
"""
import logging

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import auth
import config
import db
import models
import schemas
import server_crypto as sc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
# Structured event logger. We deliberately log only event names + non-secret
# identifiers — NEVER request bodies for auth/vault endpoints.
log = logging.getLogger("passvault")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PassVault", version="0.2.0")
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
def _ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "rate_limited"})


app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.on_event("startup")
def _startup():
    db.init_db()
    log.info("event=startup db=%s origins=%s", config.DB_PATH, config.ALLOWED_ORIGINS)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(body: schemas.RegisterIn, session: Session = Depends(db.get_db)):
    email = body.email.strip().lower()
    user = models.User(
        email=email,
        kdf_salt=body.kdfSalt,
        kdf_params=body.kdfParams,
        server_auth_hash=sc.hash_auth(body.authHash),
        protected_vault_key=body.protectedVaultKey,
        recovery_salt=body.recoverySalt,
        recovery_protected_vault_key=body.recoveryProtectedVaultKey,
        server_recovery_auth_hash=sc.hash_auth(body.recoveryAuthHash),
        totp_enabled=False,
    )
    user.vault = models.Vault(encrypted_blob=body.vaultBlob, version=1)
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="email_exists")
    log.info("event=register user=%s", user.id)
    return {"ok": True}


@app.post("/api/prelogin", response_model=schemas.PreloginOut)
@limiter.limit(config.RATE_LIMIT_AUTH)
def prelogin(
    request: Request,
    body: schemas.PreloginIn,
    session: Session = Depends(db.get_db),
):
    email = body.email.strip().lower()
    user = session.query(models.User).filter(models.User.email == email).first()
    if user is not None:
        return schemas.PreloginOut(kdfSalt=user.kdf_salt, kdfParams=user.kdf_params)
    # Unknown email: return a deterministic fake salt + default params so known
    # and unknown accounts are indistinguishable.
    return schemas.PreloginOut(
        kdfSalt=sc.fake_salt(email), kdfParams=config.DEFAULT_KDF_PARAMS
    )


@app.post("/api/login", response_model=schemas.LoginOut)
@limiter.limit(config.RATE_LIMIT_AUTH)
def login(
    request: Request,
    body: schemas.LoginIn,
    session: Session = Depends(db.get_db),
):
    email = body.email.strip().lower()
    user = session.query(models.User).filter(models.User.email == email).first()

    invalid = HTTPException(status_code=401, detail="invalid_credentials")
    if user is None:
        sc.dummy_verify()  # equalize timing for unknown accounts
        raise invalid
    if not sc.verify_auth(user.server_auth_hash, body.authHash):
        raise invalid

    if user.totp_enabled:
        import totp

        if not body.totpCode or not totp.verify(user.totp_secret, body.totpCode):
            raise HTTPException(status_code=401, detail="totp_required")

    token = auth.create_access_token(user.id)
    log.info("event=login user=%s", user.id)
    return schemas.LoginOut(token=token, protectedVaultKey=user.protected_vault_key)


@app.post("/api/tg/verify")
@limiter.limit(config.RATE_LIMIT_AUTH)
def tg_verify(request: Request, body: schemas.TgVerifyIn):
    """Confirm a Mini App WebView was genuinely launched from Telegram.

    Convenience / anti-embedding check only — NOT the auth boundary. The real
    auth is still email + master password (zero-knowledge). We never log the
    initData (it carries user info) nor the result payload.
    """
    if not config.TELEGRAM_BOT_TOKEN:
        raise HTTPException(status_code=503, detail="tg_not_configured")
    data = sc.verify_telegram_init_data(body.initData, config.TELEGRAM_BOT_TOKEN)
    if data is None:
        raise HTTPException(status_code=401, detail="invalid_init_data")
    log.info("event=tg_verify ok")
    return {"ok": True}


# ---------------------------------------------------------------------------
# M7 — password change, recovery, and TOTP.
#
# password change & recovery stay INSIDE the zero-knowledge boundary: the client
# re-derives keys and re-wraps the SAME vaultKey, then uploads ciphertext +
# hashes only. The server never sees the master password or the recovery code.
# TOTP is the one server-side factor (secret stored in plaintext) and is
# intentionally OUTSIDE the zero-knowledge boundary — see models.py / README.
# ---------------------------------------------------------------------------
@app.post("/api/password/change")
def password_change(
    body: schemas.PasswordChangeIn,
    user: models.User = Depends(auth.get_current_user),
    session: Session = Depends(db.get_db),
):
    """Re-key the master password. Vault blob and recovery bundle are untouched
    (the vaultKey itself does not change), so the recovery code still works."""
    user.kdf_salt = body.kdfSalt
    user.server_auth_hash = sc.hash_auth(body.authHash)
    user.protected_vault_key = body.protectedVaultKey
    session.commit()
    log.info("event=password_change user=%s", user.id)
    return {"ok": True}


@app.post("/api/recovery/rotate")
def recovery_rotate(
    body: schemas.RecoveryRotateIn,
    user: models.User = Depends(auth.get_current_user),
    session: Session = Depends(db.get_db),
):
    """Regenerate the recovery code (settings screen). Stores the new recovery
    bundle for the SAME vaultKey; the previous recovery code stops working."""
    user.recovery_salt = body.recoverySalt
    user.recovery_protected_vault_key = body.recoveryProtectedVaultKey
    user.server_recovery_auth_hash = sc.hash_auth(body.recoveryAuthHash)
    session.commit()
    log.info("event=recovery_rotate user=%s", user.id)
    return {"ok": True}


@app.post("/api/recover/prelogin", response_model=schemas.RecoverPreloginOut)
@limiter.limit(config.RATE_LIMIT_AUTH)
def recover_prelogin(
    request: Request,
    body: schemas.RecoverPreloginIn,
    session: Session = Depends(db.get_db),
):
    """Hand back the recovery salt + wrapped vaultKey so the client can attempt
    a recovery. Useless without the recovery code. For unknown emails we return a
    deterministic fake bundle so accounts can't be enumerated."""
    email = body.email.strip().lower()
    user = session.query(models.User).filter(models.User.email == email).first()
    if user is not None and user.recovery_salt and user.recovery_protected_vault_key:
        return schemas.RecoverPreloginOut(
            recoverySalt=user.recovery_salt,
            recoveryProtectedVaultKey=user.recovery_protected_vault_key,
        )
    fake = sc.fake_recovery(email)
    return schemas.RecoverPreloginOut(
        recoverySalt=fake["recoverySalt"],
        recoveryProtectedVaultKey=fake["recoveryProtectedVaultKey"],
    )


@app.post("/api/recover")
@limiter.limit(config.RATE_LIMIT_AUTH)
def recover(
    request: Request,
    body: schemas.RecoverIn,
    session: Session = Depends(db.get_db),
):
    """Prove possession of the recovery code (via recoveryAuthHash) and set a new
    master password. Vault blob is untouched. On success the OLD master password
    no longer works; the recovery code is unchanged (re-derived to the same key).

    Break-glass: the recovery code ALSO clears TOTP. The intended scenario is a
    user who lost BOTH their master password and their phone — possession of the
    recovery code is itself a strong factor, so we don't strand them behind a
    second factor they can no longer satisfy. They can re-enroll TOTP afterward."""
    email = body.email.strip().lower()
    user = session.query(models.User).filter(models.User.email == email).first()
    invalid = HTTPException(status_code=401, detail="invalid_recovery")
    if user is None or not user.server_recovery_auth_hash:
        sc.dummy_verify()  # equalize timing for unknown / no-recovery accounts
        raise invalid
    if not sc.verify_auth(user.server_recovery_auth_hash, body.recoveryAuthHash):
        raise invalid
    user.kdf_salt = body.newKdfSalt
    user.server_auth_hash = sc.hash_auth(body.newAuthHash)
    user.protected_vault_key = body.newProtectedVaultKey
    user.totp_enabled = False
    user.totp_secret = None
    session.commit()
    log.info("event=recover user=%s totp_cleared=1", user.id)
    return {"ok": True}


@app.post("/api/totp/enroll", response_model=schemas.TotpEnrollOut)
def totp_enroll(
    user: models.User = Depends(auth.get_current_user),
    session: Session = Depends(db.get_db),
):
    """Begin TOTP enrollment: generate a fresh secret (stored but NOT yet
    enabled) and return the otpauth URI + QR. Requires the user to disable an
    existing TOTP first, so we never clobber a working secret."""
    import totp

    if user.totp_enabled:
        raise HTTPException(status_code=409, detail="totp_already_enabled")
    secret = totp.new_secret()
    user.totp_secret = secret
    user.totp_enabled = False
    session.commit()
    uri = totp.provisioning_uri(secret, user.email)
    log.info("event=totp_enroll user=%s", user.id)
    return schemas.TotpEnrollOut(otpauthUri=uri, qrPng=totp.qr_png_data_uri(uri))


@app.post("/api/totp/confirm")
def totp_confirm(
    body: schemas.TotpCodeIn,
    user: models.User = Depends(auth.get_current_user),
    session: Session = Depends(db.get_db),
):
    """Verify a code against the pending secret and enable TOTP."""
    import totp

    if user.totp_enabled:
        return {"ok": True}
    if not user.totp_secret or not totp.verify(user.totp_secret, body.code):
        raise HTTPException(status_code=400, detail="invalid_code")
    user.totp_enabled = True
    session.commit()
    log.info("event=totp_confirm user=%s", user.id)
    return {"ok": True}


@app.post("/api/totp/disable")
@limiter.limit(config.RATE_LIMIT_AUTH)
def totp_disable(
    request: Request,
    body: schemas.TotpCodeIn,
    user: models.User = Depends(auth.get_current_user),
    session: Session = Depends(db.get_db),
):
    """Verify a current code, then disable TOTP and wipe the secret.

    Rate-limited (per-IP) so the 6-digit code can't be brute-forced even by an
    already-authenticated session."""
    import totp

    if not user.totp_enabled:
        return {"ok": True}
    if not totp.verify(user.totp_secret, body.code):
        raise HTTPException(status_code=400, detail="invalid_code")
    user.totp_enabled = False
    user.totp_secret = None
    session.commit()
    log.info("event=totp_disable user=%s", user.id)
    return {"ok": True}


@app.get("/api/vault", response_model=schemas.VaultOut)
def get_vault(
    user: models.User = Depends(auth.get_current_user),
    session: Session = Depends(db.get_db),
):
    vault = session.get(models.Vault, user.id)
    if vault is None:
        raise HTTPException(status_code=404, detail="no_vault")
    return schemas.VaultOut(
        encryptedBlob=vault.encrypted_blob, version=vault.version
    )


@app.put("/api/vault")
def put_vault(
    body: schemas.VaultPutIn,
    user: models.User = Depends(auth.get_current_user),
    session: Session = Depends(db.get_db),
):
    vault = session.get(models.Vault, user.id)
    if vault is None:
        raise HTTPException(status_code=404, detail="no_vault")
    # Optimistic concurrency: the client must send the version it last saw.
    if body.version != vault.version:
        return JSONResponse(
            status_code=409,
            content={"error": "conflict", "serverVersion": vault.version},
        )
    vault.encrypted_blob = body.encryptedBlob
    vault.version += 1
    session.commit()
    log.info("event=vault_put user=%s version=%s", user.id, vault.version)
    return {"version": vault.version}

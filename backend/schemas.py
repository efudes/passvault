"""Pydantic request/response models.

Field names are camelCase to match the JS clients exactly (the client does ALL
crypto and sends only ciphertext + hashes).
"""
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    kdfSalt: str
    kdfParams: dict
    authHash: str
    protectedVaultKey: str
    vaultBlob: str
    recoverySalt: str
    recoveryProtectedVaultKey: str
    recoveryAuthHash: str


class PreloginIn(BaseModel):
    email: EmailStr


class PreloginOut(BaseModel):
    kdfSalt: str
    kdfParams: dict


class LoginIn(BaseModel):
    email: EmailStr
    authHash: str
    totpCode: Optional[str] = None


class LoginOut(BaseModel):
    token: str
    protectedVaultKey: str


class VaultOut(BaseModel):
    encryptedBlob: str
    version: int


class VaultPutIn(BaseModel):
    encryptedBlob: str
    version: int = Field(ge=0)


class VaultPutOut(BaseModel):
    version: int


class PasswordChangeIn(BaseModel):
    kdfSalt: str
    authHash: str
    protectedVaultKey: str


class RecoverPreloginIn(BaseModel):
    email: EmailStr


class RecoverPreloginOut(BaseModel):
    recoverySalt: str
    recoveryProtectedVaultKey: str


class RecoverIn(BaseModel):
    email: EmailStr
    recoveryAuthHash: str
    newKdfSalt: str
    newAuthHash: str
    newProtectedVaultKey: str


class RecoveryRotateIn(BaseModel):
    # Re-key the recovery bundle from the *settings* screen ("regenerate recovery
    # code"). Carries only ciphertext + a hash — never the recovery code itself.
    recoverySalt: str
    recoveryProtectedVaultKey: str
    recoveryAuthHash: str


class TotpCodeIn(BaseModel):
    code: str


class TotpEnrollOut(BaseModel):
    otpauthUri: str
    qrPng: str  # data URI (base64 PNG)


class TgVerifyIn(BaseModel):
    # Raw Telegram.WebApp.initData query string. Verified server-side against the
    # bot token. This is a convenience / anti-embedding check ONLY — NOT the auth
    # boundary (real auth is still email + master password, zero-knowledge).
    initData: str

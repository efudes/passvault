"""SQLAlchemy ORM models.

The server stores ONLY: opaque ciphertext blobs, salts, wrapped keys, an
argon2id hash of the client authHash, and TOTP secrets. No plaintext vault data,
no master password, no derived keys ever touch this table.
"""
import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(
        String(320), unique=True, index=True, nullable=False
    )
    kdf_salt: Mapped[str] = mapped_column(Text, nullable=False)  # b64
    kdf_params: Mapped[dict] = mapped_column(JSON, nullable=False)
    # argon2id hash (at rest) of the client-supplied authHash.
    server_auth_hash: Mapped[str] = mapped_column(Text, nullable=False)
    protected_vault_key: Mapped[str] = mapped_column(Text, nullable=False)  # b64

    recovery_salt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recovery_protected_vault_key: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    server_recovery_auth_hash: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    # SECURITY NOTE: TOTP secret is stored in plaintext because it is a
    # server-side verification factor, NOT part of the zero-knowledge boundary.
    # Protect via OS disk encryption + strict DB file permissions (see README).
    totp_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    vault: Mapped["Vault"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )


class Vault(Base):
    __tablename__ = "vaults"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    encrypted_blob: Mapped[str] = mapped_column(Text, nullable=False)  # b64
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="vault")

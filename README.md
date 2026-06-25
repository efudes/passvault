# 🔐 PassVault

> Zero-knowledge encrypted password manager with browser extension, Telegram Mini App, and self-hosted backend.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?logo=fastapi&logoColor=white)
![MV3](https://img.shields.io/badge/Extension-Manifest_V3-4285F4?logo=googlechrome&logoColor=white)
![Telegram](https://img.shields.io/badge/Telegram-Mini_App-2CA5E0?logo=telegram&logoColor=white)
![Self-hosted](https://img.shields.io/badge/Self--hosted-VPS-black?logo=linux&logoColor=white)

---

## Overview

PassVault is a personal password manager built around a **zero-knowledge** principle — the server never sees plaintext passwords. All encryption and decryption happens client-side using AES-256-GCM. The system consists of three components that can be used independently or together.

## Architecture

```
┌─────────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
│   Browser Extension │     │  Telegram Mini App   │     │    FastAPI Backend  │
│      (MV3)          │────▶│   (shared vaults)    │────▶│   (self-hosted VPS) │
│  AES-256-GCM client │     │  AES-256-GCM client  │     │   stores ciphertext │
└─────────────────────┘     └──────────────────────┘     └─────────────────────┘
```

### Components

| Component | Stack | Status |
|-----------|-------|--------|
| **Crypto core** | AES-256-GCM, PBKDF2, zero-knowledge | ✅ Done |
| **FastAPI backend** | Python, SQLite, JWT auth | ✅ Done |
| **Shared vault web client** | HTML/JS, client-side crypto | ✅ Done |
| **Production deploy** | Nginx, TLS, systemd, Ubuntu 22.04 | ✅ Done |
| **Browser extension** | Manifest V3, Chrome/Firefox | 🔧 In progress |
| **Telegram Mini App** | TWA, shared vaults | 🔧 In progress |
| **TOTP / Recovery codes** | RFC 6238 | 📋 Planned |

## Security Model

- **Master password** is never transmitted — used locally to derive encryption key via PBKDF2
- **AES-256-GCM** encryption on the client before any data leaves the device
- **Server stores only ciphertext** — a compromised backend reveals nothing
- JWT-based authentication for API access
- TLS termination via Nginx on production

## Self-Hosting

```bash
# Clone and set up
git clone https://github.com/efudes/passvault
cd passvault
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env: SECRET_KEY, DATABASE_URL

# Run
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Production deployment uses **systemd** service + **Nginx** reverse proxy with Let's Encrypt TLS.

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy, SQLite, python-jose (JWT), passlib
- **Crypto:** AES-256-GCM, PBKDF2-HMAC-SHA256 (client-side JS / WebCrypto API)
- **Extension:** Manifest V3, Chrome Extensions API
- **Infra:** Ubuntu 22.04, Nginx, systemd, HostZealot VPS

## Project Structure

```
passvault/
├── backend/             # FastAPI backend
│   ├── main.py          #   API entry point
│   ├── models.py        #   SQLAlchemy models
│   ├── schemas.py       #   Pydantic schemas
│   ├── auth.py          #   JWT auth
│   ├── server_crypto.py #   server-side crypto helpers
│   ├── totp.py          #   TOTP (2FA)
│   ├── config.py
│   └── db.py
├── crypto/              # Client-side crypto core (AES-256-GCM, Argon2)
├── vault-web/           # Shared vault web UI / Telegram Mini App
├── bot/                 # Telegram bot (opens the Mini App)
├── extension/           # MV3 browser extension
└── deploy/              # Nginx, systemd units, setup/backup scripts
```

---

*Built as a learning project to explore zero-knowledge architecture and browser extension development.*

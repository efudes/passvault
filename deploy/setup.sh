#!/usr/bin/env bash
# PassVault VPS provisioning. Idempotent: safe to re-run. Run as root on the
# server AFTER rsync'ing the repo to $APP_DIR. Brings up venv, systemd service,
# nginx, and a Let's Encrypt cert, then health-checks the live HTTPS endpoint.
#
#   sudo APP_DIR=/opt/passvault DOMAIN=example.com ADMIN_EMAIL=you@example.com \
#        bash /opt/passvault/deploy/setup.sh
#
# Secrets (JWT_SECRET, SERVER_HMAC_SECRET) are generated HERE, on the server,
# with `openssl rand -hex 48`. They are written only to $APP_DIR/.env (chmod 600,
# owned by the service user) and never leave the box / never touch the repo.
set -euo pipefail

# ---- Config (override via environment) ----
APP_DIR="${APP_DIR:-/opt/passvault}"
DOMAIN="${DOMAIN:-example.com}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"   # Let's Encrypt expiry notices
SVC_USER="passvault"
WEBROOT="/var/www/certbot"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)." >&2; exit 1; fi
if [[ ! -d "$APP_DIR/backend" ]]; then
  echo "Repo not found at $APP_DIR (rsync it first)." >&2; exit 1
fi

# ---- 1. System packages ----
log "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# age + gnupg = backup encryption; unzip = installing the official rclone binary.
apt-get install -y python3 python3-venv python3-pip nginx certbot \
                   sqlite3 openssl curl age gnupg unzip

# ---- 1b. rclone (for offsite R2 backups) ----
# Ubuntu 22.04's apt rclone (1.53) predates the Cloudflare S3 provider, so install
# the official static binary to /usr/local/bin (which shadows any apt rclone).
# Idempotent: skip if a usable rclone is already on PATH.
if ! command -v rclone >/dev/null 2>&1; then
  log "Installing rclone (official static binary)"
  rc_tmp="$(mktemp -d)"
  curl -fsSL -o "$rc_tmp/rclone.zip" https://downloads.rclone.org/rclone-current-linux-amd64.zip
  unzip -q "$rc_tmp/rclone.zip" -d "$rc_tmp"
  install -m 0755 "$rc_tmp"/rclone-*-linux-amd64/rclone /usr/local/bin/rclone
  rm -rf "$rc_tmp"
  # `| head` would SIGPIPE rclone and trip pipefail; read the version safely.
  rclone_ver="$(rclone version)"; printf '%s\n' "${rclone_ver%%$'\n'*}"
else
  log "rclone already installed: $(command -v rclone)"
fi

# ---- 2. Service user ----
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  log "Creating system user $SVC_USER"
  useradd --system --create-home --home-dir "/home/$SVC_USER" \
          --shell /usr/sbin/nologin "$SVC_USER"
fi

# ---- 3. Directories ----
log "Creating data/backup directories"
mkdir -p "$APP_DIR/data" "$APP_DIR/backups" "$WEBROOT"
chown -R "$SVC_USER:$SVC_USER" "$APP_DIR/data" "$APP_DIR/backups"
chmod 700 "$APP_DIR/data" "$APP_DIR/backups"
# nginx (www-data) needs to read the app tree; service user owns data dirs.
chown -R root:root "$APP_DIR/backend" "$APP_DIR/crypto" "$APP_DIR/vault-web" "$APP_DIR/deploy"
[[ -d "$APP_DIR/bot" ]] && chown -R root:root "$APP_DIR/bot"
# Public extension download dir (the built .zip rsync'd in with the repo). nginx
# serves it from location /download/. Create even if empty so the location works.
mkdir -p "$APP_DIR/download"
chown -R root:root "$APP_DIR/download"
chmod 755 "$APP_DIR/download"

# ---- 4. Python venv + dependencies ----
log "Building Python virtualenv"
if [[ ! -x "$APP_DIR/backend/.venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/backend/.venv"
fi
"$APP_DIR/backend/.venv/bin/pip" install --upgrade pip
"$APP_DIR/backend/.venv/bin/pip" install -r "$APP_DIR/backend/requirements.txt"

# ---- 5. .env with server-generated secrets (only if absent) ----
if [[ ! -f "$APP_DIR/.env" ]]; then
  log "Generating $APP_DIR/.env with fresh secrets"
  JWT_SECRET="$(openssl rand -hex 48)"
  SERVER_HMAC_SECRET="$(openssl rand -hex 48)"
  cat > "$APP_DIR/.env" <<EOF
DOMAIN=$DOMAIN
ALLOWED_ORIGINS=https://$DOMAIN
JWT_SECRET=$JWT_SECRET
SERVER_HMAC_SECRET=$SERVER_HMAC_SECRET
TELEGRAM_BOT_TOKEN=
PASSVAULT_DB=$APP_DIR/data/passvault.db
JWT_TTL_HOURS=12
EOF
else
  log ".env already exists — leaving secrets untouched"
fi
chown "$SVC_USER:$SVC_USER" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

# ---- 6. systemd unit ----
log "Installing systemd unit"
sed "s#__APP_DIR__#$APP_DIR#g" "$APP_DIR/deploy/passvault.service" \
    > /etc/systemd/system/passvault.service
systemctl daemon-reload
systemctl enable passvault
systemctl restart passvault

# ---- 7. nginx HTTP bootstrap (so certbot webroot works before cert exists) ----
log "Writing HTTP bootstrap nginx site"
cat > /etc/nginx/sites-available/passvault <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 200 'passvault bootstrap'; add_header Content-Type text/plain; }
}
EOF
ln -sf /etc/nginx/sites-available/passvault /etc/nginx/sites-enabled/passvault
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

# ---- 8. Let's Encrypt certificate (webroot, non-interactive) ----
if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
  log "Obtaining Let's Encrypt certificate for $DOMAIN"
  certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" \
          --non-interactive --agree-tos -m "$ADMIN_EMAIL"
else
  log "Certificate for $DOMAIN already present — skipping issuance"
fi

# ---- 9. Full TLS nginx site ----
log "Installing full TLS nginx site"
sed -e "s#__DOMAIN__#$DOMAIN#g" -e "s#__APP_DIR__#$APP_DIR#g" \
    "$APP_DIR/deploy/nginx.conf" > /etc/nginx/sites-available/passvault
nginx -t
systemctl reload nginx

# certbot installs a systemd timer for renewal automatically; make sure nginx
# picks up the renewed cert via a deploy hook.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/usr/bin/env bash
systemctl reload nginx
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

# ---- 10. Nightly backup cron ----
log "Installing nightly backup cron"
sed "s#__APP_DIR__#$APP_DIR#g" "$APP_DIR/deploy/backup.sh" > "$APP_DIR/deploy/backup.run.sh"
chmod +x "$APP_DIR/deploy/backup.run.sh"
chown "$SVC_USER:$SVC_USER" "$APP_DIR/deploy/backup.run.sh"
cat > /etc/cron.d/passvault-backup <<EOF
# PassVault nightly DB backup at 03:17
17 3 * * * $SVC_USER $APP_DIR/deploy/backup.run.sh >> $APP_DIR/backups/backup.log 2>&1
EOF
chmod 644 /etc/cron.d/passvault-backup

# ---- 10b. Telegram bot (optional; enabled only when a token is configured) ----
log "Configuring Telegram bot"
BOT_TOKEN="$(sed -n 's/^TELEGRAM_BOT_TOKEN=//p' "$APP_DIR/.env" | head -n1)"
BOT_TOKEN="${BOT_TOKEN%\"}"; BOT_TOKEN="${BOT_TOKEN#\"}"
BOT_TOKEN="${BOT_TOKEN%\'}"; BOT_TOKEN="${BOT_TOKEN#\'}"
if [[ -n "${BOT_TOKEN:-}" && -f "$APP_DIR/bot/bot.py" ]]; then
  if [[ ! -x "$APP_DIR/bot/.venv/bin/python" ]]; then
    python3 -m venv "$APP_DIR/bot/.venv"
  fi
  "$APP_DIR/bot/.venv/bin/pip" install --upgrade pip
  "$APP_DIR/bot/.venv/bin/pip" install -r "$APP_DIR/bot/requirements.txt"
  sed "s#__APP_DIR__#$APP_DIR#g" "$APP_DIR/deploy/passvault-bot.service" \
      > /etc/systemd/system/passvault-bot.service
  systemctl daemon-reload
  systemctl enable passvault-bot
  systemctl restart passvault-bot
  log "Telegram bot enabled (token present)."
else
  log "TELEGRAM_BOT_TOKEN empty — skipping bot. Set it in $APP_DIR/.env and re-run to enable."
fi

# ---- 11. Smoke test ----
log "Smoke test: https://$DOMAIN/api/health"
sleep 2
code="$(curl -sS -o /tmp/pv_health.json -w '%{http_code}' "https://$DOMAIN/api/health" || true)"
echo "HTTP $code"; cat /tmp/pv_health.json 2>/dev/null || true; echo
if [[ "$code" == "200" ]]; then
  log "DEPLOY OK — health check returned 200 over HTTPS"
else
  echo "Health check did NOT return 200 (got $code). Inspect:" >&2
  echo "  journalctl -u passvault -n 50 --no-pager" >&2
  echo "  systemctl status nginx" >&2
  exit 1
fi

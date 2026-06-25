#!/usr/bin/env bash
# PassVault nightly backup. Installed to __APP_DIR__/deploy/backup.sh by setup.sh
# (which substitutes __APP_DIR__ and writes backup.run.sh) and run via cron as the
# passvault user.
#
# Two layers:
#   1. LOCAL  — sqlite3 .backup snapshot in $APP_DIR/backups (kept 14 days).
#   2. OFFSITE — encrypted tar of {passvault.db, .env} uploaded to Cloudflare R2,
#                keeping the newest 14 objects.
#
# The offsite layer is OPTIONAL: if the R2_* / BACKUP_ENCRYPTION_KEY variables are
# empty or missing, the script performs the local backup, prints a warning, and
# exits 0 (cron must never start failing just because offsite isn't configured).
#
# Secrets are read from the environment, which is loaded from $APP_DIR/.env (cron
# has no EnvironmentFile). Nothing sensitive is ever placed on a command line:
#   - rclone reads R2 creds from RCLONE_S3_* env vars (not argv).
#   - the encryption key/passphrase is fed via a file descriptor / key file.
set -euo pipefail
cd /   # never depend on the caller's cwd (cron/sudo may start in an unreadable dir)

APP_DIR="__APP_DIR__"
DB="${PASSVAULT_DB:-$APP_DIR/data/passvault.db}"
ENV_FILE="$APP_DIR/.env"
BACKUP_DIR="$APP_DIR/backups"
KEEP_LOCAL_DAYS=14
KEEP_REMOTE=14

stamp="$(date +%Y%m%d-%H%M%S)"
warn() { printf 'WARN: %s\n' "$*" >&2; }
log()  { printf '%s\n' "$*"; }

# ---- Load only whitelisted vars from .env (no `source`, so values can't run
#      shell code; values may contain '=' and optional surrounding quotes). ----
load_env() {
  local f="$1" k v
  [[ -f "$f" ]] || return 0
  while IFS='=' read -r k v; do
    case "$k" in
      R2_ACCOUNT_ID|R2_ACCESS_KEY_ID|R2_SECRET_ACCESS_KEY|R2_BUCKET|R2_ENDPOINT|\
      R2_PREFIX|RCLONE_S3_PROVIDER|BACKUP_ENCRYPTION_KEY)
        v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
        # Don't clobber a value already exported in the real environment.
        [[ -z "${!k:-}" ]] && export "$k=$v"
        ;;
    esac
  done < "$f"
}
load_env "$ENV_FILE"

# ============================================================================
# 1. LOCAL snapshot (consistent even under concurrent writes)
# ============================================================================
mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
local_db="$BACKUP_DIR/passvault-$stamp.db"
sqlite3 "$DB" ".backup '$local_db'"
chmod 600 "$local_db"
find "$BACKUP_DIR" -name 'passvault-*.db' -type f -mtime +"$KEEP_LOCAL_DAYS" -delete
log "local backup ok: $local_db"

# ============================================================================
# 2. OFFSITE encrypted upload to Cloudflare R2 (optional)
# ============================================================================
missing=()
for v in R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY R2_BUCKET R2_ENDPOINT BACKUP_ENCRYPTION_KEY; do
  [[ -z "${!v:-}" ]] && missing+=("$v")
done
if (( ${#missing[@]} )); then
  warn "offsite backup skipped — unset: ${missing[*]} (local backup is done)"
  exit 0
fi

# Pick encryption tool: prefer age, fall back to gpg.
ENC_TOOL=""
if command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1; then
  ENC_TOOL="age"
elif command -v gpg >/dev/null 2>&1; then
  ENC_TOOL="gpg"
else
  warn "offsite backup skipped — neither age nor gpg is installed"
  exit 0
fi
if ! command -v rclone >/dev/null 2>&1; then
  warn "offsite backup skipped — rclone is not installed"
  exit 0
fi

# Secure scratch dir; wiped on exit no matter what.
work="$(mktemp -d)"; chmod 700 "$work"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

# Stage the two files to archive: the consistent DB snapshot + live .env.
stage="$work/passvault-$stamp"
mkdir -p "$stage"
cp -p "$local_db" "$stage/passvault.db"
if [[ -f "$ENV_FILE" ]]; then cp -p "$ENV_FILE" "$stage/.env"; else warn ".env not found; archiving DB only"; fi
archive="$work/passvault-$stamp.tar.gz"
tar -C "$work" -czf "$archive" "passvault-$stamp"

# Encrypt -> object name. age => .age, gpg => .gpg (restore.sh keys off the ext).
case "$ENC_TOOL" in
  age)
    keyfile="$work/age.key"; (umask 077; printf '%s\n' "$BACKUP_ENCRYPTION_KEY" > "$keyfile")
    pub="$(age-keygen -y "$keyfile" 2>/dev/null || true)"
    if [[ -z "$pub" ]]; then
      warn "BACKUP_ENCRYPTION_KEY is not a valid age secret key (expected 'AGE-SECRET-KEY-1...'). Generate one with: age-keygen. Offsite skipped."
      exit 0
    fi
    enc="$work/passvault-$stamp.age"
    age -r "$pub" -o "$enc" "$archive"
    ;;
  gpg)
    enc="$work/passvault-$stamp.gpg"
    printf '%s' "$BACKUP_ENCRYPTION_KEY" | \
      gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
          --symmetric --cipher-algo AES256 -o "$enc" "$archive"
    ;;
esac
obj="$(basename "$enc")"

# rclone S3 backend configured purely via env (creds never hit argv).
export RCLONE_S3_PROVIDER="${RCLONE_S3_PROVIDER:-Cloudflare}"
export RCLONE_S3_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
export RCLONE_S3_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
export RCLONE_S3_ENDPOINT="$R2_ENDPOINT"
export RCLONE_S3_REGION="${RCLONE_S3_REGION:-auto}"
export RCLONE_S3_NO_CHECK_BUCKET=true
prefix="${R2_PREFIX:-}"
base=":s3:${R2_BUCKET}${prefix:+/$prefix}"

rclone copyto "$enc" "$base/$obj"
log "offsite upload ok: $base/$obj"

# ---- Retention: keep newest $KEEP_REMOTE objects, delete older ----
mapfile -t objs < <(rclone lsf "$base" 2>/dev/null \
  | grep -E '^passvault-[0-9]{8}-[0-9]{6}\.(age|gpg)$' | sort)
total=${#objs[@]}
if (( total > KEEP_REMOTE )); then
  for old in "${objs[@]:0:total-KEEP_REMOTE}"; do
    rclone deletefile "$base/$old" && log "pruned remote: $old"
  done
fi

log "backup complete (local + offsite, $ENC_TOOL): $obj"

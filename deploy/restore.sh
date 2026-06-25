#!/usr/bin/env bash
# PassVault disaster recovery: pull an encrypted backup from Cloudflare R2,
# decrypt it, and drop passvault.db + .env back into place.
#
# IMPORTANT — bootstrap problem: the R2 credentials and the decryption key live
# INSIDE the encrypted backup (in .env), so on a brand-new VPS they are not yet
# available on disk. Therefore restore.sh reads everything from the ENVIRONMENT,
# which you export by hand for this one command. Example:
#
#   export R2_ACCESS_KEY_ID=...        \
#          R2_SECRET_ACCESS_KEY=...    \
#          R2_BUCKET=passvault-backups \
#          R2_ENDPOINT=https://<accountid>.r2.cloudflarestorage.com \
#          BACKUP_ENCRYPTION_KEY='AGE-SECRET-KEY-1...'   # or your gpg passphrase
#   sudo -E APP_DIR=/opt/passvault bash deploy/restore.sh           # latest backup
#   sudo -E APP_DIR=/opt/passvault bash deploy/restore.sh passvault-20260623-031701.age
#
# Flags:
#   --force    overwrite existing passvault.db/.env (otherwise they're preserved
#              and the restored copies are written as *.restored next to them)
set -euo pipefail
cd /   # never depend on the caller's cwd

APP_DIR="${APP_DIR:-/opt/passvault}"
SVC_USER="${SVC_USER:-passvault}"
WANT="" ; FORCE=0
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *)  WANT="$a" ;;
  esac
done

die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log()  { printf '%s\n' "$*"; }

# ---- Required env ----
for v in R2_ACCESS_KEY_ID R2_SECRET_ACCESS_KEY R2_BUCKET R2_ENDPOINT BACKUP_ENCRYPTION_KEY; do
  [[ -n "${!v:-}" ]] || die "export $v before running restore (see header)"
done
command -v rclone >/dev/null 2>&1 || die "rclone not installed (run setup.sh or apt/official install)"

export RCLONE_S3_PROVIDER="${RCLONE_S3_PROVIDER:-Cloudflare}"
export RCLONE_S3_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
export RCLONE_S3_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
export RCLONE_S3_ENDPOINT="$R2_ENDPOINT"
export RCLONE_S3_REGION="${RCLONE_S3_REGION:-auto}"
prefix="${R2_PREFIX:-}"
base=":s3:${R2_BUCKET}${prefix:+/$prefix}"

# ---- Choose object: explicit name, or newest passvault-*.{age,gpg} ----
if [[ -z "$WANT" ]]; then
  WANT="$(rclone lsf "$base" 2>/dev/null \
    | grep -E '^passvault-[0-9]{8}-[0-9]{6}\.(age|gpg)$' | sort | tail -n1 || true)"
  [[ -n "$WANT" ]] || die "no passvault-*.{age,gpg} objects found in $base"
fi
log "restoring from: $base/$WANT"

work="$(mktemp -d)"; chmod 700 "$work"
trap 'rm -rf "$work"' EXIT

enc="$work/$WANT"
rclone copyto "$base/$WANT" "$enc" || die "download failed"

# ---- Decrypt by extension ----
archive="$work/restore.tar.gz"
case "$WANT" in
  *.age)
    command -v age >/dev/null 2>&1 || die "age not installed but backup is .age"
    keyfile="$work/age.key"; (umask 077; printf '%s\n' "$BACKUP_ENCRYPTION_KEY" > "$keyfile")
    age -d -i "$keyfile" -o "$archive" "$enc" || die "age decryption failed (wrong key?)"
    ;;
  *.gpg)
    command -v gpg >/dev/null 2>&1 || die "gpg not installed but backup is .gpg"
    printf '%s' "$BACKUP_ENCRYPTION_KEY" | \
      gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
          -d -o "$archive" "$enc" || die "gpg decryption failed (wrong passphrase?)"
    ;;
  *) die "unrecognized backup extension: $WANT" ;;
esac

# ---- Extract ----
ex="$work/x"; mkdir -p "$ex"
tar -C "$ex" -xzf "$archive"
inner="$(find "$ex" -maxdepth 1 -type d -name 'passvault-*' | head -n1)"
[[ -n "$inner" && -f "$inner/passvault.db" ]] || die "archive missing passvault.db"

# ---- Place files ----
mkdir -p "$APP_DIR/data"
place() {  # src dest
  local src="$1" dest="$2"
  if [[ -e "$dest" && $FORCE -eq 0 ]]; then
    cp -p "$src" "$dest.restored"
    log "exists, kept original: wrote $dest.restored (use --force to overwrite)"
  else
    cp -p "$src" "$dest"
    log "restored: $dest"
  fi
}
place "$inner/passvault.db" "$APP_DIR/data/passvault.db"
[[ -f "$inner/.env" ]] && place "$inner/.env" "$APP_DIR/.env" || log "(no .env in archive)"

# ---- Ownership / perms (best effort) ----
if id -u "$SVC_USER" >/dev/null 2>&1; then
  chown "$SVC_USER:$SVC_USER" "$APP_DIR/data/passvault.db" 2>/dev/null || true
  [[ -f "$APP_DIR/.env" ]] && chown "$SVC_USER:$SVC_USER" "$APP_DIR/.env" 2>/dev/null || true
fi
chmod 600 "$APP_DIR/data/passvault.db" 2>/dev/null || true
[[ -f "$APP_DIR/.env" ]] && chmod 600 "$APP_DIR/.env" 2>/dev/null || true

log ""
log "Restore done. Next: run setup.sh to (re)provision, or just:"
log "  systemctl restart passvault && curl -fsS https://\$DOMAIN/api/health"

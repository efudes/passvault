#!/usr/bin/env bash
# Build the PassVault MV3 browser extension for internal sideloading.
#
# The extension popup is the SHARED vault-web UI (crypto/ + vault-web/) reused
# verbatim. This script assembles a self-contained package by copying those
# directories next to the extension's own manifest, preserving the relative
# layout that vault-web/app.js expects ("../crypto/crypto.js"). The only swap is
# config.js: the packaged copy is replaced with config.ext.js so the popup points
# at the production backend (the repo's vault-web/config.js stays same-origin for
# the Telegram Mini App).
#
# Outputs:
#   dist/passvault-extension/         <- load this "unpacked" via chrome://extensions
#   dist/passvault-extension.zip      <- zip for distributing to colleagues
#   ../download/passvault-extension.zip <- copy nginx serves at /download/ (synced
#                                         to the server, published by setup.sh)
#
# Load unpacked: chrome://extensions -> enable "Developer mode" -> "Load unpacked"
# -> select dist/passvault-extension. No Chrome Web Store flow.
set -euo pipefail
cd "$(dirname "$0")"                 # extension/
ROOT="$(cd .. && pwd)"              # passvault/
OUT="dist"
PKG="$OUT/passvault-extension"
DOWNLOAD_DIR="$ROOT/download"        # nginx serves this at https://<domain>/download/

[[ -f "$ROOT/crypto/crypto.js" ]]        || { echo "ERROR: crypto/ not found at repo root"; exit 1; }
[[ -f "$ROOT/vault-web/index.html" ]]    || { echo "ERROR: vault-web/ not found at repo root"; exit 1; }

echo "==> cleaning $OUT"
rm -rf "$OUT"
mkdir -p "$PKG"

echo "==> copying extension manifest"
cp manifest.json "$PKG/manifest.json"

echo "==> copying shared crypto/ and vault-web/ (verbatim)"
cp -r "$ROOT/crypto"    "$PKG/crypto"
cp -r "$ROOT/vault-web" "$PKG/vault-web"

echo "==> swapping in extension config (prod backend, cross-origin)"
cp config.ext.js "$PKG/vault-web/config.js"

echo "==> adding popup-only sizing CSS (linked only in the packaged index.html)"
cp popup.css "$PKG/vault-web/popup.css"
# Inject the popup.css <link> right after the styles.css <link>. We edit only the
# PACKAGED copy of index.html — the repo's vault-web/index.html stays untouched so
# the Mini App (M6) keeps its full-width responsive layout.
idx="$PKG/vault-web/index.html"
sed 's#\(<link rel="stylesheet" href="./styles.css" />\)#\1\n    <link rel="stylesheet" href="./popup.css" />#' \
    "$idx" > "$idx.tmp" && mv "$idx.tmp" "$idx"
grep -q 'href="./popup.css"' "$idx" \
  || { echo "ERROR: failed to inject popup.css link into packaged index.html"; exit 1; }

# Strip any stray test harness from the package (not needed at runtime).
rm -f "$PKG/crypto/crypto.test.html"

echo "==> zipping"
ZIP_PATH=""
if command -v zip >/dev/null 2>&1; then
  ( cd "$OUT" && zip -qr passvault-extension.zip passvault-extension )
  ZIP_PATH="$(pwd)/$OUT/passvault-extension.zip"
elif command -v powershell.exe >/dev/null 2>&1; then
  # Windows dev box without the 'zip' CLI: fall back to PowerShell.
  powershell.exe -NoProfile -Command \
    "Compress-Archive -Force -Path '$PKG' -DestinationPath '$OUT\\passvault-extension.zip'" \
    && ZIP_PATH="$(pwd)/$OUT/passvault-extension.zip"
else
  echo "   (no 'zip' or PowerShell found — skipping zip; the unpacked dir is enough to sideload)"
fi

# Publish the zip into the repo's download/ dir. This is what gets rsync'd to the
# server and served by nginx at https://<domain>/download/passvault-extension.zip
# (setup.sh creates $APP_DIR/download and chowns it for nginx).
if [[ -n "$ZIP_PATH" ]]; then
  echo "==> publishing zip to download/ (served by nginx at /download/)"
  mkdir -p "$DOWNLOAD_DIR"
  cp -f "$ZIP_PATH" "$DOWNLOAD_DIR/passvault-extension.zip"
fi

echo
echo "Build complete:"
echo "  unpacked dir : $(pwd)/$PKG"
[[ -n "$ZIP_PATH" ]] && echo "  zip          : $ZIP_PATH"
[[ -n "$ZIP_PATH" ]] && echo "  published    : $DOWNLOAD_DIR/passvault-extension.zip"
echo
echo "Load it: chrome://extensions -> Developer mode -> Load unpacked -> select the unpacked dir."

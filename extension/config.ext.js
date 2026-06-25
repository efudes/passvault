// Extension popup configuration.
//
// build.sh copies this file over vault-web/config.js INSIDE the packaged
// extension (the build artifact under dist/), so the popup talks to the
// production backend cross-origin. That cross-origin access is granted by the
// "host_permissions" entry in manifest.json, which lets the extension page
// fetch https://example.com without being subject to the server's CORS list.
//
// The repo's own vault-web/config.js is left untouched (apiBase: "") because the
// Telegram Mini App (M6) serves the same UI same-origin and needs the empty base.
window.PASSVAULT_CONFIG = {
  apiBase: "https://example.com",
  autoLockMs: 3 * 60 * 1000, // 3 minutes inactivity -> wipe keys
  clipboardClearMs: 30 * 1000, // clear clipboard 30s after copy
};

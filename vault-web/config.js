// Shared client config. This file is reused verbatim by the extension popup and
// the Telegram Mini App.
//
// apiBase: leave "" to talk to the same origin (Mini App served from the backend
// at /app, or extension pointed at its configured backend). For local dev you can
// override at runtime without editing code:
//   localStorage.setItem("pv_api_base", "http://127.0.0.1:8732")
window.PASSVAULT_CONFIG = {
  apiBase: "",
  autoLockMs: 3 * 60 * 1000, // 3 minutes inactivity -> wipe keys
  clipboardClearMs: 30 * 1000, // clear clipboard 30s after copy
};

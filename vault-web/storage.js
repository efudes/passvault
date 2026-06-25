// PassVault local-storage abstraction for the optional PIN quick-unlock block.
//
// A SINGLE interface (`pinStore`) with TWO backends, chosen at load time, so the
// PIN crypto logic in app.js is written once and never duplicated per client:
//
//   • Browser extension popup  -> chrome.storage.local   (MV3 promise API)
//   • Telegram Mini App / web  -> window.localStorage     (WebView-local only)
//
// CRITICAL (Mini App): we deliberately use the WebView's own localStorage and
// NEVER Telegram CloudStorage. CloudStorage syncs through Telegram's servers,
// which would push the (encrypted) block off-device — violating the requirement
// that the block stay strictly local to this device. localStorage is sandboxed
// to this origin in this WebView and never leaves the phone.
//
// What is stored is ONLY the encrypted PIN block produced by crypto.wrapWithPin:
// { v, email, salt, kdfParams, pinProtectedKey, sessionToken, fails }. There is
// no plaintext vaultKey, no PIN, no master password — by construction.

const KEY = "pv_pin_v1";

// Detect the extension backend: chrome.storage.local exists in the MV3 popup.
const hasChromeStorage =
  typeof chrome !== "undefined" &&
  chrome.storage &&
  chrome.storage.local &&
  typeof chrome.storage.local.get === "function";

const backendName = hasChromeStorage ? "chrome.storage.local" : "localStorage";

async function rawGet() {
  if (hasChromeStorage) {
    const obj = await chrome.storage.local.get(KEY);
    return obj && Object.prototype.hasOwnProperty.call(obj, KEY)
      ? obj[KEY]
      : null;
  }
  const s = localStorage.getItem(KEY);
  return s == null ? null : JSON.parse(s);
}

async function rawSet(value) {
  if (hasChromeStorage) {
    await chrome.storage.local.set({ [KEY]: value });
    return;
  }
  localStorage.setItem(KEY, JSON.stringify(value));
}

async function rawRemove() {
  if (hasChromeStorage) {
    await chrome.storage.local.remove(KEY);
    return;
  }
  localStorage.removeItem(KEY);
}

export const pinStore = {
  // Human-readable name of the active backend (for the on-screen proof / debug).
  backend: backendName,

  // Returns the stored PIN block object, or null if none / unparseable.
  async load() {
    try {
      return await rawGet();
    } catch {
      return null;
    }
  },

  // Persist the PIN block object (already encrypted by crypto.wrapWithPin).
  async save(obj) {
    await rawSet(obj);
  },

  // Irreversibly remove the PIN block (sign-out, disable, lockout, MP change).
  async clear() {
    try {
      await rawRemove();
    } catch {
      /* best-effort */
    }
  },
};

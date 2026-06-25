// PassVault vault-web client. Reused verbatim by the extension popup and the
// Telegram Mini App. All crypto runs here on the client via crypto/crypto.js.
import * as cv from "../crypto/crypto.js";
import { api } from "./api.js";
import { pinStore } from "./storage.js";

const CFG = window.PASSVAULT_CONFIG || {};
const AUTO_LOCK_MS = CFG.autoLockMs ?? 180000;
const CLIP_MS = CFG.clipboardClearMs ?? 30000;
const MIN_PW = 8;
// After this many consecutive wrong PINs the on-disk block is destroyed for good
// (the counter lives INSIDE the block, so closing/reopening can't reset it).
const PIN_MAX_FAILS = 5;

// --- In-memory session. Secrets (encKey, vaultKey) live ONLY here, never in
// storage. lockedContext holds NON-secret material so we can re-derive on unlock
// without a round trip.
const session = {
  token: null,
  email: null,
  encKey: null, // Uint8Array
  vaultKey: null, // Uint8Array
  items: null, // array
  version: 0,
  lockedContext: null, // { kdfSalt, kdfParams, protectedVaultKey }
  totpEnabled: false, // tracked client-side (login demanded a code => enabled)
  pinEnabled: false, // a PIN quick-unlock block exists on THIS device
};
let lockTimer = null;
let clipTimer = null;
let editingId = null;
// Email shown on the PIN screen (so "Use master password" can prefill login even
// when the in-memory session was wiped, e.g. after a popup close).
let pinScreenEmail = "";

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const screens = document.querySelectorAll(".screen");

// Launch context (set by telegram.js before this module runs). Used to hide the
// corner "download extension / open bot" links where they make no sense.
const IN_TELEGRAM = Boolean(window.PASSVAULT_IN_TELEGRAM);
const IS_EXTENSION =
  typeof location !== "undefined" && location.protocol === "chrome-extension:";

// The corner links belong on the landing/auth screens of the plain web app only.
const PRE_AUTH_SCREENS = new Set(["login", "register", "recover"]);

function updateCornerLinks(name) {
  const box = $("cornerLinks");
  if (!box) return;
  // Never inside the Telegram Mini App; otherwise only on the pre-auth screens.
  box.hidden = IN_TELEGRAM || !PRE_AUTH_SCREENS.has(name);
  // Inside the extension popup the "download extension" link is redundant.
  const dl = $("dlExtLink");
  if (dl) dl.hidden = IS_EXTENSION;
}

function show(name) {
  screens.forEach((s) =>
    s.classList.toggle("active", s.dataset.screen === name)
  );
  const unlocked = name === "vault" || name === "settings";
  $("navLock").hidden = !unlocked;
  $("navSettings").hidden = !unlocked;
  updateCornerLinks(name);
}

let toastTimer = null;
function toast(msg, kind = "") {
  const t = $("toast");
  t.textContent = msg;
  t.className = "show" + (kind ? " toast-" + kind : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), 2600);
}

// ---------------------------------------------------------------------------
// Auto-lock + secret wiping
// ---------------------------------------------------------------------------
function wipe(arr) {
  if (arr && arr.fill) arr.fill(0);
}
function armAutoLock() {
  clearTimeout(lockTimer);
  if (session.vaultKey) lockTimer = setTimeout(lock, AUTO_LOCK_MS);
}
function lock() {
  // Preserve non-secret context so the unlock screen can re-derive.
  wipe(session.encKey);
  wipe(session.vaultKey);
  session.encKey = null;
  session.vaultKey = null;
  session.items = null;
  clearTimeout(lockTimer);
  clearClipboardSoon(true);
  closeModal();
  chooseLockScreen();
}

// Decide which locked screen to show. Prefer PIN quick-unlock if a block exists
// on this device; else fall back to the master-password unlock; else sign out.
async function chooseLockScreen() {
  const block = await pinStore.load().catch(() => null);
  if (block && block.pinProtectedKey) {
    showPinScreen(block);
    return;
  }
  if (session.lockedContext && session.token) {
    $("unlockWho").textContent = `Signed in as ${session.email}`;
    $("unlockPassword").value = "";
    $("unlockErr").textContent = "";
    show("unlock");
    $("unlockPassword").focus();
    return;
  }
  signOut();
}
["click", "keydown", "mousemove", "input", "touchstart"].forEach((ev) =>
  document.addEventListener(ev, () => session.vaultKey && armAutoLock(), {
    passive: true,
  })
);

function signOut() {
  wipe(session.encKey);
  wipe(session.vaultKey);
  Object.assign(session, {
    token: null,
    encKey: null,
    vaultKey: null,
    items: null,
    version: 0,
    lockedContext: null,
    totpEnabled: false,
    pinEnabled: false,
  });
  clearTimeout(lockTimer);
  // Signing out erases the PIN quick-unlock block on this device.
  pinStore.clear();
  show("login");
  $("loginPassword").value = "";
  $("loginEmail").value = localStorage.getItem("pv_last_email") || "";
}

// Return to a full master-password login WITHOUT destroying the PIN block (e.g.
// the persisted token expired, or the user chose "Use master password"). A fresh
// login will refresh the stored token, keeping quick-unlock working.
function goToLoginPrefill(email) {
  wipe(session.encKey);
  wipe(session.vaultKey);
  Object.assign(session, {
    token: null,
    encKey: null,
    vaultKey: null,
    items: null,
    version: 0,
    lockedContext: null,
    totpEnabled: false,
  });
  clearTimeout(lockTimer);
  show("login");
  $("loginPassword").value = "";
  $("loginEmail").value =
    email || localStorage.getItem("pv_last_email") || "";
  $("loginPassword").focus();
}

// ---------------------------------------------------------------------------
// Clipboard (auto-clear)
// ---------------------------------------------------------------------------
let lastCopied = null;
async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    lastCopied = text;
    toast(`${label} copied — clears in ${CLIP_MS / 1000}s`, "ok");
    clearTimeout(clipTimer);
    clipTimer = setTimeout(() => clearClipboardSoon(false), CLIP_MS);
  } catch {
    toast("Clipboard blocked by browser", "err");
  }
}
async function clearClipboardSoon(immediate) {
  clearTimeout(clipTimer);
  if (!lastCopied) return;
  try {
    // Only clear if what we copied is (likely) still there.
    const cur = await navigator.clipboard.readText().catch(() => null);
    if (immediate || cur === null || cur === lastCopied) {
      await navigator.clipboard.writeText("");
    }
  } catch {
    /* best effort */
  }
  lastCopied = null;
}

// ---------------------------------------------------------------------------
// Conflict-safe save. `mutate(items)` must be idempotent (upsert/remove by id)
// so it can be re-applied after refetching on a 409.
// ---------------------------------------------------------------------------
async function commit(mutate) {
  for (let attempt = 0; attempt < 3; attempt++) {
    mutate(session.items);
    const blob = await cv.sealVault(session.vaultKey, session.items);
    const res = await api.putVault(session.token, blob, session.version);
    if (res.ok) {
      session.version = res.data.version;
      return true;
    }
    if (res.status === 409) {
      // Vault changed elsewhere: pull latest, decrypt, loop re-applies mutate.
      const fresh = await api.getVault(session.token);
      if (!fresh.ok) throw new Error("refetch_failed");
      session.items = await cv.decryptJson(
        session.vaultKey,
        fresh.data.encryptedBlob
      );
      session.version = fresh.data.version;
      toast("Vault was updated elsewhere — merged", "");
      continue;
    }
    if (res.status === 401) {
      lock();
      throw new Error("session_locked");
    }
    throw new Error("save_failed_" + res.status);
  }
  throw new Error("conflict_retry_exhausted");
}

// ---------------------------------------------------------------------------
// Vault rendering
// ---------------------------------------------------------------------------
function enterVault() {
  localStorage.setItem("pv_last_email", session.email);
  renderList();
  show("vault");
  armAutoLock();
}

function renderList() {
  const q = $("search").value.trim().toLowerCase();
  const items = (session.items || [])
    .slice()
    .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
    .filter(
      (it) =>
        !q ||
        [it.title, it.username, it.url].some((v) =>
          (v || "").toLowerCase().includes(q)
        )
    );
  $("vaultCount").textContent = `${session.items.length} entr${
    session.items.length === 1 ? "y" : "ies"
  } · v${session.version}`;
  const list = $("list");
  list.innerHTML = "";
  $("emptyState").hidden = session.items.length !== 0;
  for (const it of items) {
    const el = document.createElement("div");
    el.className = "entry";
    el.innerHTML = `
      <div class="meta">
        <div class="title"></div>
        <div class="sub"></div>
      </div>
      <div class="actions">
        <button class="iconbtn" data-act="user" title="Copy username">usr</button>
        <button class="iconbtn" data-act="pass" title="Copy password">pwd</button>
        <button class="iconbtn" data-act="edit" title="Edit">edit</button>
      </div>`;
    el.querySelector(".title").textContent = it.title || "(untitled)";
    el.querySelector(".sub").textContent = it.username || it.url || "";
    el.querySelector('[data-act="user"]').onclick = () =>
      copyText(it.username || "", "Username");
    el.querySelector('[data-act="pass"]').onclick = () =>
      copyText(it.password || "", "Password");
    el.querySelector('[data-act="edit"]').onclick = () => openEdit(it.id);
    list.appendChild(el);
  }
}

// ---------------------------------------------------------------------------
// Add / edit modal
// ---------------------------------------------------------------------------
function openEdit(id) {
  editingId = id || null;
  const it = id ? session.items.find((x) => x.id === id) : null;
  $("editTitle").textContent = id ? "Edit entry" : "Add entry";
  $("fTitle").value = it?.title || "";
  $("fUsername").value = it?.username || "";
  $("fPassword").value = it?.password || "";
  $("fUrl").value = it?.url || "";
  $("fNotes").value = it?.notes || "";
  $("editErr").textContent = "";
  $("editModal").classList.add("active");
  $("fTitle").focus();
}
function closeModal() {
  $("editModal").classList.remove("active");
  editingId = null;
}
function genPassword(len = 20) {
  const set =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+";
  const buf = crypto.getRandomValues(new Uint32Array(len));
  let out = "";
  for (let i = 0; i < len; i++) out += set[buf[i] % set.length];
  return out;
}
async function saveEdit() {
  const item = {
    id: editingId || crypto.randomUUID(),
    title: $("fTitle").value.trim(),
    username: $("fUsername").value,
    password: $("fPassword").value,
    url: $("fUrl").value.trim(),
    notes: $("fNotes").value,
    updatedAt: Date.now(),
  };
  if (!item.title && !item.username && !item.url) {
    $("editErr").textContent = "Add at least a title, username, or URL.";
    return;
  }
  try {
    await commit((items) => {
      const i = items.findIndex((x) => x.id === item.id);
      if (i >= 0) items[i] = item;
      else items.push(item);
    });
    closeModal();
    renderList();
    toast("Saved", "ok");
  } catch (e) {
    if (e.message !== "session_locked")
      $("editErr").textContent = "Save failed: " + e.message;
  }
}
async function deleteEntry(id) {
  if (!confirm("Delete this entry?")) return;
  try {
    await commit((items) => {
      const i = items.findIndex((x) => x.id === id);
      if (i >= 0) items.splice(i, 1);
    });
    renderList();
    toast("Deleted", "ok");
  } catch (e) {
    if (e.message !== "session_locked") toast("Delete failed", "err");
  }
}

// ---------------------------------------------------------------------------
// Auth flows
// ---------------------------------------------------------------------------
async function doRegister() {
  const email = $("regEmail").value.trim().toLowerCase();
  const pw = $("regPassword").value;
  const pw2 = $("regPassword2").value;
  const err = $("regErr");
  err.textContent = "";
  if (!email) return (err.textContent = "Email required.");
  if (pw.length < MIN_PW)
    return (err.textContent = `Master password needs ≥ ${MIN_PW} chars.`);
  if (pw !== pw2) return (err.textContent = "Passwords don't match.");
  setBusy("regBtn", true, "Creating…");
  try {
    const { registration, recoveryCode, secrets } = await cv.createAccount(
      pw,
      email,
      []
    );
    const reg = await api.register(registration);
    if (!reg.ok) {
      if (reg.status === 409) throw new Error("That email is already registered.");
      throw new Error("Registration failed.");
    }
    // Obtain a session token via the normal login path.
    const login = await api.login(email, registration.authHash);
    if (!login.ok) throw new Error("Auto-login after register failed.");
    session.token = login.data.token;
    session.email = email;
    session.encKey = secrets.encKey;
    session.vaultKey = secrets.vaultKey;
    session.items = [];
    session.version = 1;
    session.lockedContext = {
      kdfSalt: registration.kdfSalt,
      kdfParams: registration.kdfParams,
      protectedVaultKey: registration.protectedVaultKey,
    };
    // Show the recovery code ONCE.
    $("recoveryCode").textContent = recoveryCode;
    $("recoveryAck").checked = false;
    $("recoveryDone").disabled = true;
    show("recovery");
  } catch (e) {
    err.textContent = e.message;
  } finally {
    setBusy("regBtn", false, "Create account");
  }
}

async function doLogin() {
  const email = $("loginEmail").value.trim().toLowerCase();
  const pw = $("loginPassword").value;
  const totp = $("loginTotp").value.trim();
  const err = $("loginErr");
  err.textContent = "";
  if (!email || !pw) return (err.textContent = "Email and password required.");
  setBusy("loginBtn", true, "Unlocking…");
  try {
    const pre = await api.prelogin(email);
    if (!pre.ok) throw new Error("Server unavailable.");
    const { encKey, authHash } = await cv.computeLoginAuth(pw, pre.data);
    const login = await api.login(email, authHash, totp || undefined);
    if (!login.ok) {
      if (login.status === 401 && login.data?.detail === "totp_required") {
        $("loginTotpWrap").hidden = false;
        err.textContent = totp
          ? "Invalid authenticator code."
          : "Enter your authenticator code.";
        $("loginTotp").focus();
        return;
      }
      throw new Error("Invalid email or master password.");
    }
    const vault = await api.getVault(login.data.token);
    if (!vault.ok) throw new Error("Could not load vault.");
    const protectedVaultKey = login.data.protectedVaultKey;
    const vaultKey = await cv.aesGcmDecrypt(encKey, protectedVaultKey);
    const items = await cv.decryptJson(vaultKey, vault.data.encryptedBlob);
    session.token = login.data.token;
    session.email = email;
    session.encKey = encKey;
    session.vaultKey = vaultKey;
    session.items = items;
    session.version = vault.data.version;
    session.lockedContext = {
      kdfSalt: pre.data.kdfSalt,
      kdfParams: pre.data.kdfParams,
      protectedVaultKey,
    };
    // If the server demanded a TOTP code (i.e. we sent one and it was accepted),
    // TOTP is enabled for this account — remember it for the settings screen.
    session.totpEnabled = Boolean(totp);
    $("loginTotpWrap").hidden = true;
    $("loginTotp").value = "";
    enterVault();
    // If quick-unlock is on for this device, refresh the encrypted stored token
    // (we have the vaultKey now, so no PIN is needed to re-wrap it).
    refreshPinToken();
  } catch (e) {
    err.textContent = e.message || "Sign-in failed.";
  } finally {
    setBusy("loginBtn", false, "Unlock vault");
  }
}

async function doUnlock() {
  const pw = $("unlockPassword").value;
  const err = $("unlockErr");
  err.textContent = "";
  if (!pw) return;
  setBusy("unlockBtn", true, "Unlocking…");
  try {
    const ctx = session.lockedContext;
    const { encKey } = await cv.computeLoginAuth(pw, ctx);
    const vault = await api.getVault(session.token);
    if (vault.status === 401) {
      // token expired -> require a fresh login
      toast("Session expired — sign in again", "");
      $("loginEmail").value = session.email;
      signOut();
      $("loginEmail").value = session.email;
      return;
    }
    if (!vault.ok) throw new Error("Could not load vault.");
    const vaultKey = await cv.aesGcmDecrypt(encKey, ctx.protectedVaultKey);
    const items = await cv.decryptJson(vaultKey, vault.data.encryptedBlob);
    session.encKey = encKey;
    session.vaultKey = vaultKey;
    session.items = items;
    session.version = vault.data.version;
    enterVault();
    refreshPinToken();
  } catch (e) {
    err.textContent = "Wrong master password.";
  } finally {
    setBusy("unlockBtn", false, "Unlock");
  }
}

// ---------------------------------------------------------------------------
// PIN quick-unlock (optional, client-only). See crypto.js for the wrap scheme:
// pinKey = Argon2id(PIN, salt); on disk lives ONLY AES-GCM(pinKey, vaultKey) plus
// the salt, an encrypted session token, and a fail counter. The PIN itself and
// the plaintext vaultKey are NEVER written. The server never participates.
// ---------------------------------------------------------------------------
function showPinScreen(block) {
  pinScreenEmail = block?.email || session.email || "";
  $("pinWho").textContent = pinScreenEmail
    ? `Signed in as ${pinScreenEmail}`
    : "";
  $("pinInput").value = "";
  $("pinErr").textContent = "";
  show("pin");
  $("pinInput").focus();
}

async function doPinUnlock() {
  const pin = $("pinInput").value.trim();
  const err = $("pinErr");
  err.textContent = "";
  if (!pin) return;
  const block = await pinStore.load().catch(() => null);
  if (!block || !block.pinProtectedKey) {
    goToLoginPrefill(pinScreenEmail);
    return;
  }
  setBusy("pinUnlockBtn", true, "Unlocking…");
  try {
    let unwrapped;
    try {
      // GCM auth failure here == wrong PIN. No plaintext is ever revealed.
      unwrapped = await cv.unwrapWithPin(pin, block);
    } catch {
      const fails = (block.fails || 0) + 1;
      if (fails >= PIN_MAX_FAILS) {
        // Irreversibly destroy the block — only the master password works now.
        await pinStore.clear();
        session.pinEnabled = false;
        toast("Too many wrong PINs — quick unlock erased", "err");
        goToLoginPrefill(block.email);
      } else {
        block.fails = fails; // persist the counter INSIDE the on-disk block
        await pinStore.save(block);
        err.textContent = `Wrong PIN — ${PIN_MAX_FAILS - fails} attempt(s) left.`;
        $("pinInput").value = "";
        $("pinInput").focus();
      }
      return;
    }
    // Correct PIN: reset the counter, then use the (decrypted) token to load.
    const { vaultKey, token } = unwrapped;
    const useToken = token || session.token;
    if (!useToken) {
      wipe(vaultKey);
      toast("Session expired — sign in again", "");
      goToLoginPrefill(block.email);
      return;
    }
    const vault = await api.getVault(useToken);
    if (vault.status === 401) {
      // Token no longer valid: keep the block, re-auth with master password.
      wipe(vaultKey);
      toast("Session expired — sign in again", "");
      goToLoginPrefill(block.email);
      return;
    }
    if (!vault.ok) throw new Error("Could not load vault.");
    const items = await cv.decryptJson(vaultKey, vault.data.encryptedBlob);
    if (block.fails) {
      block.fails = 0;
      await pinStore.save(block);
    }
    session.token = useToken;
    session.email = block.email;
    session.encKey = null; // not derived on the PIN path (no master password)
    session.vaultKey = vaultKey;
    session.items = items;
    session.version = vault.data.version;
    session.lockedContext = null; // re-lock will route back to the PIN screen
    session.pinEnabled = true;
    enterVault();
    // Keep the stored token fresh (we used session.token if the stored one was
    // stale) so the next quick-unlock has a current token.
    refreshPinToken();
  } catch (e) {
    err.textContent = e.message || "Unlock failed.";
  } finally {
    setBusy("pinUnlockBtn", false, "Unlock");
  }
}

// Re-wrap the current session token against an existing PIN block. Uses the
// vaultKey (available after any successful unlock), so it needs NO PIN. No-op if
// quick-unlock isn't enabled on this device.
async function refreshPinToken() {
  if (!session.vaultKey || !session.token) return;
  const block = await pinStore.load().catch(() => null);
  if (!block || !block.salt) return;
  try {
    block.sessionToken = await cv.rewrapPinToken(
      session.vaultKey,
      block.salt,
      session.token
    );
    await pinStore.save(block);
    session.pinEnabled = true;
  } catch {
    /* leave the existing block as-is */
  }
}

async function enablePin() {
  const pin = $("pinNew").value.trim();
  const pin2 = $("pinNew2").value.trim();
  const err = $("pinErrSet");
  err.textContent = "";
  if (!/^\d{4,8}$/.test(pin))
    return (err.textContent = "PIN must be 4–8 digits.");
  if (pin !== pin2) return (err.textContent = "PINs don't match.");
  if (!session.vaultKey || !session.token)
    return (err.textContent = "Unlock the vault first.");
  setBusy("pinEnableBtn", true, "Enabling…");
  try {
    const wrapped = await cv.wrapWithPin(pin, session.vaultKey, session.token);
    // The on-disk block: email + salt + kdfParams + wrapped key + wrapped token
    // + fail counter. NO plaintext PIN, NO plaintext vaultKey.
    await pinStore.save({ v: 1, email: session.email, ...wrapped, fails: 0 });
    session.pinEnabled = true;
    $("pinNew").value = "";
    $("pinNew2").value = "";
    refreshPinUI(true);
    toast("Quick unlock enabled", "ok");
  } catch (e) {
    err.textContent = e.message || "Failed to enable.";
  } finally {
    setBusy("pinEnableBtn", false, "Enable quick unlock");
  }
}

async function disablePin() {
  await pinStore.clear();
  session.pinEnabled = false;
  refreshPinUI(false);
  toast("Quick unlock disabled", "ok");
}

async function refreshPinUI(enabled) {
  if (enabled === undefined) {
    const block = await pinStore.load().catch(() => null);
    enabled = Boolean(block && block.pinProtectedKey);
  }
  session.pinEnabled = enabled;
  $("pinStatus").textContent = enabled ? "Enabled (this device)" : "Disabled";
  $("pinBackend").textContent = pinStore.backend;
  $("pinEnableArea").hidden = enabled;
  $("pinDisableArea").hidden = !enabled;
  $("pinNew").value = "";
  $("pinNew2").value = "";
  $("pinErrSet").textContent = "";
}

function setBusy(id, busy, label) {
  const b = $(id);
  b.disabled = busy;
  if (label) b.textContent = label;
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
async function openSettings() {
  $("setEmail").textContent = session.email;
  $("setCount").textContent = session.items.length;
  $("setVersion").textContent = "v" + session.version;
  $("cpNew").value = "";
  $("cpNew2").value = "";
  $("cpErr").textContent = "";
  refreshTotpUI(session.totpEnabled);
  await refreshPinUI(); // detect from disk whether a PIN block exists here
  show("settings");
}

function refreshTotpUI(enabled) {
  session.totpEnabled = enabled;
  $("totpStatus").textContent = enabled ? "Enabled" : "Disabled";
  $("totpEnrollBtn").hidden = enabled;
  $("totpEnrollArea").hidden = true;
  $("totpDisableArea").hidden = !enabled;
  $("totpDisableCode").value = "";
}

// --- Change master password: re-derive + re-wrap the SAME vaultKey client-side.
async function doChangePassword() {
  const pw = $("cpNew").value;
  const pw2 = $("cpNew2").value;
  const err = $("cpErr");
  err.textContent = "";
  if (pw.length < MIN_PW)
    return (err.textContent = `New master password needs ≥ ${MIN_PW} chars.`);
  if (pw !== pw2) return (err.textContent = "Passwords don't match.");
  setBusy("cpBtn", true, "Changing…");
  try {
    const ch = await cv.changePassword(pw, session.vaultKey);
    const res = await api.passwordChange(session.token, {
      kdfSalt: ch.kdfSalt,
      authHash: ch.authHash,
      protectedVaultKey: ch.protectedVaultKey,
    });
    if (res.status === 401) return lock();
    if (!res.ok) throw new Error("Server rejected the change.");
    // Update in-memory context so auto-lock re-derivation uses the new password.
    session.encKey = ch.secrets.encKey;
    session.lockedContext = {
      kdfSalt: ch.kdfSalt,
      kdfParams: ch.kdfParams,
      protectedVaultKey: ch.protectedVaultKey,
    };
    // A master-password change erases any PIN quick-unlock block on this device.
    await pinStore.clear();
    session.pinEnabled = false;
    refreshPinUI(false);
    $("cpNew").value = "";
    $("cpNew2").value = "";
    toast("Master password changed — re-enable quick unlock if you want it", "ok");
  } catch (e) {
    err.textContent = e.message || "Change failed.";
  } finally {
    setBusy("cpBtn", false, "Change password");
  }
}

// --- TOTP enroll / confirm / disable (server-side second factor) ---
async function totpEnroll() {
  setBusy("totpEnrollBtn", true, "…");
  try {
    const res = await api.totpEnroll(session.token);
    if (res.status === 401) return lock();
    if (res.status === 409) {
      refreshTotpUI(true);
      return toast("TOTP already enabled", "");
    }
    if (!res.ok) throw new Error("Enroll failed");
    $("totpQr").src = res.data.qrPng;
    $("totpUri").textContent = res.data.otpauthUri;
    $("totpEnrollArea").hidden = false;
    $("totpConfirmCode").value = "";
    $("totpConfirmCode").focus();
  } catch (e) {
    toast(e.message || "Enroll failed", "err");
  } finally {
    setBusy("totpEnrollBtn", false, "Enable TOTP");
  }
}
async function totpConfirm() {
  const code = $("totpConfirmCode").value.trim();
  if (!code) return;
  const res = await api.totpConfirm(session.token, code);
  if (res.status === 401) return lock();
  if (!res.ok) return toast("Invalid code", "err");
  refreshTotpUI(true);
  toast("Two-factor enabled", "ok");
}
async function totpDisable() {
  const code = $("totpDisableCode").value.trim();
  if (!code) return;
  const res = await api.totpDisable(session.token, code);
  if (res.status === 401) return lock();
  if (!res.ok) return toast("Invalid code", "err");
  refreshTotpUI(false);
  toast("Two-factor disabled", "ok");
}

// --- Regenerate recovery code: re-wrap the SAME vaultKey, show the new code once.
async function regenRecovery() {
  if (
    !confirm(
      "Generate a new recovery code? Your OLD recovery code will stop working."
    )
  )
    return;
  setBusy("regenRecBtn", true, "…");
  try {
    const { recoveryCode, recovery } = await cv.regenerateRecovery(
      session.vaultKey
    );
    const res = await api.recoveryRotate(session.token, recovery);
    if (res.status === 401) return lock();
    if (!res.ok) throw new Error("Server rejected the rotation.");
    $("recoveryCode").textContent = recoveryCode;
    $("recoveryAck").checked = false;
    $("recoveryDone").disabled = true;
    show("recovery"); // reuses the "save your code once" screen
  } catch (e) {
    toast(e.message || "Failed", "err");
  } finally {
    setBusy("regenRecBtn", false, "Regenerate recovery code");
  }
}

// --- Recover with code: unwrap vaultKey via recovery code, set a new MP. ---
async function doRecover() {
  const email = $("recEmail").value.trim().toLowerCase();
  const code = $("recCode").value.trim();
  const pw = $("recNewPw").value;
  const err = $("recErr");
  err.textContent = "";
  if (!email || !code)
    return (err.textContent = "Email and recovery code required.");
  if (pw.length < MIN_PW)
    return (err.textContent = `New master password needs ≥ ${MIN_PW} chars.`);
  setBusy("recBtn", true, "Recovering…");
  try {
    const pre = await api.recoverPrelogin(email);
    if (!pre.ok) throw new Error("Server unavailable.");
    let submit;
    try {
      // GCM auth failure here == wrong code (or unknown email -> fake bundle),
      // both surfaced identically so accounts can't be enumerated.
      ({ submit } = await cv.buildRecoverySubmit(
        code,
        {
          recoverySalt: pre.data.recoverySalt,
          recoveryProtectedVaultKey: pre.data.recoveryProtectedVaultKey,
        },
        pw
      ));
    } catch {
      throw new Error("Invalid recovery code for this account.");
    }
    const res = await api.recover({ email, ...submit });
    if (!res.ok) throw new Error("Invalid recovery code for this account.");
    $("recEmail").value = "";
    $("recCode").value = "";
    $("recNewPw").value = "";
    toast("Recovered — sign in with your new master password", "ok");
    localStorage.setItem("pv_last_email", email);
    $("loginEmail").value = email;
    show("login");
    $("loginPassword").focus();
  } catch (e) {
    err.textContent = e.message || "Recovery failed.";
  } finally {
    setBusy("recBtn", false, "Recover");
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
function wire() {
  $("toRegister").onclick = () => show("register");
  $("toLogin").onclick = () => show("login");
  $("toRecover").onclick = () => show("recover");
  $("recToLogin").onclick = () => show("login");
  $("regBtn").onclick = doRegister;
  $("loginBtn").onclick = doLogin;
  $("unlockBtn").onclick = doUnlock;
  $("unlockSignout").onclick = signOut;

  // PIN quick-unlock: lock screen + settings enable/disable.
  $("pinUnlockBtn").onclick = doPinUnlock;
  $("pinUsePassword").onclick = () => goToLoginPrefill(pinScreenEmail);
  $("pinSignout").onclick = signOut;
  $("pinInput").addEventListener(
    "keydown",
    (e) => e.key === "Enter" && doPinUnlock()
  );
  $("pinEnableBtn").onclick = enablePin;
  $("pinDisableBtn").onclick = disablePin;
  $("pinNew2").addEventListener(
    "keydown",
    (e) => e.key === "Enter" && enablePin()
  );

  $("recoveryAck").onchange = (e) =>
    ($("recoveryDone").disabled = !e.target.checked);
  $("recoveryDone").onclick = enterVault;

  // recover-with-code (M7)
  $("recBtn").onclick = doRecover;
  $("recNewPw").addEventListener(
    "keydown",
    (e) => e.key === "Enter" && doRecover()
  );

  // settings (M7): change MP, TOTP enroll/confirm/disable, regenerate recovery
  $("cpBtn").onclick = doChangePassword;
  $("totpEnrollBtn").onclick = totpEnroll;
  $("totpConfirmBtn").onclick = totpConfirm;
  $("totpDisableBtn").onclick = totpDisable;
  $("regenRecBtn").onclick = regenRecovery;
  $("totpConfirmCode").addEventListener(
    "keydown",
    (e) => e.key === "Enter" && totpConfirm()
  );
  $("totpDisableCode").addEventListener(
    "keydown",
    (e) => e.key === "Enter" && totpDisable()
  );

  $("search").oninput = renderList;
  $("addBtn").onclick = () => openEdit(null);
  $("editCancel").onclick = closeModal;
  $("editSave").onclick = saveEdit;
  $("fGen").onclick = () => ($("fPassword").value = genPassword());

  $("navLock").onclick = lock;
  $("navSettings").onclick = openSettings;
  $("setLock").onclick = lock;
  $("setSignout").onclick = signOut;
  $("setBack").onclick = () => show("vault");

  // Enter-to-submit on the auth forms.
  $("loginPassword").addEventListener("keydown", (e) => e.key === "Enter" && doLogin());
  $("loginTotp").addEventListener("keydown", (e) => e.key === "Enter" && doLogin());
  $("unlockPassword").addEventListener("keydown", (e) => e.key === "Enter" && doUnlock());
  $("regPassword2").addEventListener("keydown", (e) => e.key === "Enter" && doRegister());

  // long-press / right-click an entry to delete -> simpler: add delete via edit?
  // Provide delete from the edit modal instead.
}

// Add a Delete button to the edit modal dynamically (keeps index.html lean).
function injectDeleteButton() {
  const row = $("editCancel").parentElement;
  const del = document.createElement("button");
  del.className = "danger";
  del.textContent = "Delete";
  del.style.flex = "0 0 auto";
  del.onclick = () => editingId && deleteEntry(editingId).then(closeModal);
  del.id = "editDelete";
  row.insertBefore(del, row.firstChild);
  // hide for "add" mode
  const obs = new MutationObserver(() => {
    del.style.display = editingId ? "" : "none";
  });
  obs.observe($("editModal"), { attributes: true, attributeFilter: ["class"] });
}

// First screen at startup: if this device has a PIN quick-unlock block, offer the
// PIN screen (the popup/Mini App was closed, memory is gone, but the encrypted
// block persists). Otherwise show the normal login, prefilled with the last email.
async function startScreen() {
  const block = await pinStore.load().catch(() => null);
  if (block && block.pinProtectedKey) {
    showPinScreen(block);
  } else {
    show("login");
    $("loginEmail").value = localStorage.getItem("pv_last_email") || "";
  }
}

async function boot() {
  // Telegram Mini App: expand the WebView when launched inside Telegram (M6).
  if (window.Telegram?.WebApp) {
    try {
      window.Telegram.WebApp.ready();
      window.Telegram.WebApp.expand();
    } catch {}
  }
  wire();
  injectDeleteButton();
  await startScreen(); // PIN screen if a quick-unlock block exists, else login
  // Surface backend reachability early.
  const h = await api.health().catch(() => ({ ok: false }));
  if (!h.ok) toast("Backend not reachable at " + (api.base || "same origin"), "err");
}

boot();

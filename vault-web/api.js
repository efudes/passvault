// Thin fetch wrappers around the PassVault backend. No crypto here — callers
// pass already-encrypted blobs and already-derived hashes.

const API_BASE =
  localStorage.getItem("pv_api_base") ??
  (window.PASSVAULT_CONFIG && window.PASSVAULT_CONFIG.apiBase) ??
  "";

async function req(path, { method = "GET", token, body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }
  return { ok: res.ok, status: res.status, data };
}

export const api = {
  base: API_BASE,
  health: () => req("/api/health"),
  register: (registration) =>
    req("/api/register", { method: "POST", body: registration }),
  prelogin: (email) =>
    req("/api/prelogin", { method: "POST", body: { email } }),
  login: (email, authHash, totpCode) =>
    req("/api/login", {
      method: "POST",
      body: totpCode ? { email, authHash, totpCode } : { email, authHash },
    }),
  getVault: (token) => req("/api/vault", { token }),
  putVault: (token, encryptedBlob, version) =>
    req("/api/vault", {
      method: "PUT",
      token,
      body: { encryptedBlob, version },
    }),

  // --- M7: password change, recovery, TOTP ---
  passwordChange: (token, payload) =>
    req("/api/password/change", { method: "POST", token, body: payload }),
  recoveryRotate: (token, recovery) =>
    req("/api/recovery/rotate", { method: "POST", token, body: recovery }),
  recoverPrelogin: (email) =>
    req("/api/recover/prelogin", { method: "POST", body: { email } }),
  recover: (payload) => req("/api/recover", { method: "POST", body: payload }),
  totpEnroll: (token) => req("/api/totp/enroll", { method: "POST", token }),
  totpConfirm: (token, code) =>
    req("/api/totp/confirm", { method: "POST", token, body: { code } }),
  totpDisable: (token, code) =>
    req("/api/totp/disable", { method: "POST", token, body: { code } }),
};

// PassVault crypto core — shared client-side ES module.
//
// SECURITY MODEL (see spec section 0): every secret value below is derived,
// encrypted and decrypted ON THE CLIENT. The only values that ever leave this
// module toward the server are: authHash, protectedVaultKey, vaultBlob, salts,
// kdfParams, and (for recovery) recoveryAuthHash / recoveryProtectedVaultKey.
// The master password, masterKey, encKey, vaultKey and plaintext items NEVER
// leave the client and are never persisted to disk/storage by us.
//
// Crypto primitives: Argon2id via argon2-browser (WASM), and WebCrypto
// SubtleCrypto for AES-256-GCM, HKDF-SHA256, SHA-256 and CSPRNG.
// No other crypto libraries are used.

// ---------------------------------------------------------------------------
// argon2-browser handle. The host page (extension popup / Mini App / test page)
// must load argon2-browser's bundled build first, which defines globalThis.argon2.
// ---------------------------------------------------------------------------
function getArgon2() {
  const a = globalThis.argon2;
  if (!a || typeof a.hash !== "function") {
    throw new Error(
      "argon2-browser is not loaded. Load the bundled build (which defines " +
        "globalThis.argon2) before importing crypto.js."
    );
  }
  return a;
}

// ---------------------------------------------------------------------------
// KDF parameters. Exposed as a constant so they can be tuned and are sent to
// the server verbatim as `kdfParams`. mem is in KiB (65536 KiB = 64 MiB).
// ---------------------------------------------------------------------------
export const KDF_PARAMS = Object.freeze({
  type: "argon2id",
  mem: 65536, // KiB == 64 MiB
  time: 3,
  parallelism: 1,
  hashLen: 32,
});

// HKDF domain-separation labels. Do NOT change these strings — they are part of
// the on-the-wire format and changing them breaks every existing vault.
const INFO_ENC = "passvault-enc-v1";
const INFO_AUTH = "passvault-auth-v1";

const IV_LENGTH = 12; // AES-GCM standard 96-bit nonce
const KEY_LENGTH = 32; // 256-bit keys
const SALT_LENGTH = 16; // per-user random salt

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// ---------------------------------------------------------------------------
// Random / encoding helpers
// ---------------------------------------------------------------------------
export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function toBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function fromBase64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function utf8(str) {
  return textEncoder.encode(str);
}

// Constant-time comparison for equal-length byte arrays.
export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Argon2id KDF
// ---------------------------------------------------------------------------
// Derives a 32-byte master key from a secret (master password or recovery code)
// and a 16-byte salt. Uses Argon2id exactly per KDF_PARAMS — never substitute
// PBKDF2 or weaker parameters.
//
// SECURITY NOTE: the spec's derivation formula salts Argon2id with `kdfSalt`
// only; `email` is NOT folded into the KDF. We implement the formula exactly as
// specified (no substitutions). Per-user random salts already guarantee unique
// derivations across users; binding the email would be an additional defense but
// would deviate from the agreed scheme, so it is intentionally omitted here.
export async function deriveKeyFromSecret(secret, salt, params = KDF_PARAMS) {
  if (!(salt instanceof Uint8Array) || salt.length < 8) {
    throw new Error("salt must be a Uint8Array of at least 8 bytes");
  }
  const argon2 = getArgon2();
  const result = await argon2.hash({
    pass: secret, // string or Uint8Array accepted
    salt,
    time: params.time,
    mem: params.mem,
    parallelism: params.parallelism,
    hashLen: params.hashLen,
    type: argon2.ArgonType.Argon2id,
  });
  // result.hash is a Uint8Array of length hashLen.
  return new Uint8Array(result.hash);
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 for domain separation
// ---------------------------------------------------------------------------
async function hkdf(keyMaterial, salt, info, length = KEY_LENGTH) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    keyMaterial,
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8(info) },
    baseKey,
    length * 8
  );
  return new Uint8Array(bits);
}

// From a master key + salt, derive the encryption key and the auth hash via
// HKDF with distinct `info` labels (domain separation).
export async function deriveSubKeys(masterKey, salt) {
  const [encKey, authHash] = await Promise.all([
    hkdf(masterKey, salt, INFO_ENC, KEY_LENGTH),
    hkdf(masterKey, salt, INFO_AUTH, KEY_LENGTH),
  ]);
  return { encKey, authHash };
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------
// Encrypt -> base64(IV ‖ ciphertext‖tag). A FRESH random 12-byte IV is generated
// per call; IVs are never reused.
export async function aesGcmEncrypt(keyBytes, plaintextBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    "AES-GCM",
    false,
    ["encrypt"]
  );
  const iv = randomBytes(IV_LENGTH);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes)
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return toBase64(out);
}

// Decrypt base64(IV ‖ ciphertext‖tag). Throws (GCM auth error) on wrong key or
// tampered data — never returns silent garbage.
export async function aesGcmDecrypt(keyBytes, b64) {
  const data = fromBase64(b64);
  if (data.length <= IV_LENGTH) throw new Error("ciphertext too short");
  const iv = data.subarray(0, IV_LENGTH);
  const ct = data.subarray(IV_LENGTH);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    "AES-GCM",
    false,
    ["decrypt"]
  );
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

// JSON convenience wrappers.
export async function encryptJson(keyBytes, obj) {
  return aesGcmEncrypt(keyBytes, utf8(JSON.stringify(obj)));
}
export async function decryptJson(keyBytes, b64) {
  const pt = await aesGcmDecrypt(keyBytes, b64);
  return JSON.parse(textDecoder.decode(pt));
}

// ---------------------------------------------------------------------------
// PIN quick-unlock (optional, client-only, NEVER touches the server)
// ---------------------------------------------------------------------------
// The PIN is NOT compared against anything. It is fed through Argon2id to derive
// a key that WRAPS the real vaultKey with AES-GCM. Unlocking re-derives that key
// from the entered PIN and tries to AES-GCM-decrypt the wrapped vaultKey:
//   - GCM auth success  => correct PIN (we now hold the real vaultKey)
//   - GCM auth failure  => wrong PIN  (nothing is leaked, nothing recovered)
// So the PIN itself, the vaultKey, and the master password are NEVER stored.
// Only the wrapped blob + salt + an attempt counter live on disk.
//
// Because an unlocked session must still call the authenticated API, we also
// keep the session JWT — but encrypted, under a key derived from the vaultKey
// (HKDF, distinct label). It is therefore only recoverable AFTER a correct PIN
// has yielded the vaultKey, is never on disk in plaintext, and contains no vault
// data. This is the ONLY field beyond {wrapped vaultKey, salt, counter}.
const INFO_PIN_SESSION = "passvault-pin-session-v1";

// Reuse the strong master-password Argon2id parameters for the PIN. A 4–8 digit
// PIN has low entropy, so the irreversible 5-attempt lockout (enforced by the
// caller via the on-disk counter) is what actually bounds guessing — but using
// full-strength Argon2id still makes each on-device guess expensive.
export const PIN_KDF_PARAMS = KDF_PARAMS;

// Derive the AES key that protects the session token from the vaultKey + salt.
async function pinSessionKey(vaultKey, salt) {
  return hkdf(vaultKey, salt, INFO_PIN_SESSION, KEY_LENGTH);
}

// Wrap the vaultKey (and the session token) under a PIN. Returns the on-disk
// block fields. `salt` is fresh and random; nothing here is reversible without
// the PIN (for the vaultKey) which in turn gates the token.
export async function wrapWithPin(pin, vaultKey, token) {
  const salt = randomBytes(SALT_LENGTH);
  const pinKey = await deriveKeyFromSecret(String(pin), salt, PIN_KDF_PARAMS);
  const pinProtectedKey = await aesGcmEncrypt(pinKey, vaultKey);
  const sessKey = await pinSessionKey(vaultKey, salt);
  const sessionToken = token
    ? await aesGcmEncrypt(sessKey, utf8(token))
    : null;
  return {
    salt: toBase64(salt),
    kdfParams: { ...PIN_KDF_PARAMS },
    pinProtectedKey, // base64(IV‖GCM(pinKey, vaultKey)) — the ONLY copy of the key
    sessionToken, // base64(IV‖GCM(HKDF(vaultKey), token)) or null
  };
}

// Try to unwrap with an entered PIN. Throws (GCM auth error) on a wrong PIN.
// On success returns { vaultKey, token } (token may be null if absent/corrupt).
export async function unwrapWithPin(pin, block) {
  const salt = fromBase64(block.salt);
  const pinKey = await deriveKeyFromSecret(
    String(pin),
    salt,
    block.kdfParams || PIN_KDF_PARAMS
  );
  // GCM auth error here == wrong PIN. Caller treats the throw as a failed attempt.
  const vaultKey = await aesGcmDecrypt(pinKey, block.pinProtectedKey);
  let token = null;
  if (block.sessionToken) {
    try {
      const sessKey = await pinSessionKey(vaultKey, salt);
      token = textDecoder.decode(
        await aesGcmDecrypt(sessKey, block.sessionToken)
      );
    } catch {
      token = null; // stale/rotated token: caller will fall back to a login prompt
    }
  }
  return { vaultKey, token };
}

// Re-encrypt a fresh session token against an existing PIN block's salt, given
// the vaultKey (available right after a normal master-password login/unlock).
// Lets us refresh the stored token WITHOUT needing the PIN again.
export async function rewrapPinToken(vaultKey, saltB64, token) {
  const salt = fromBase64(saltB64);
  const sessKey = await pinSessionKey(vaultKey, salt);
  return aesGcmEncrypt(sessKey, utf8(token));
}

// ---------------------------------------------------------------------------
// Recovery code (Crockford base32, 128-bit)
// ---------------------------------------------------------------------------
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // excludes I L O U

// Generate a 128-bit recovery code, displayed grouped in 5-char chunks.
// The code is shown to the user ONCE and is never stored by us.
export function generateRecoveryCode() {
  const bytes = randomBytes(16); // 128 bits
  // Encode 8-bit groups into 5-bit symbols.
  let bits = 0;
  let value = 0;
  let symbols = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      symbols += CROCKFORD[(value >>> bits) & 31];
    }
  }
  if (bits > 0) {
    symbols += CROCKFORD[(value << (5 - bits)) & 31];
  }
  // Group into chunks of 5 separated by hyphens for readability.
  const groups = [];
  for (let i = 0; i < symbols.length; i += 5) {
    groups.push(symbols.slice(i, i + 5));
  }
  return groups.join("-");
}

// Normalize a user-entered recovery code before feeding it to the KDF, so
// display formatting (hyphens, spaces, case, Crockford I/L/O aliases) does not
// affect derivation.
export function normalizeRecoveryCode(code) {
  return code
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
}

// ---------------------------------------------------------------------------
// High-level flows
// ---------------------------------------------------------------------------

// Account creation. Returns BOTH the registration payload (server-bound,
// ciphertext + hashes only) and the in-memory secrets the client keeps.
// `recoveryCode` is returned so the UI can show it once; it is never stored.
export async function createAccount(masterPassword, email, items = []) {
  const kdfSalt = randomBytes(SALT_LENGTH);
  const masterKey = await deriveKeyFromSecret(masterPassword, kdfSalt);
  const { encKey, authHash } = await deriveSubKeys(masterKey, kdfSalt);

  const vaultKey = randomBytes(KEY_LENGTH); // real data-encryption key
  const protectedVaultKey = await aesGcmEncrypt(encKey, vaultKey);
  const vaultBlob = await encryptJson(vaultKey, items);

  // Recovery: independent key derived from a fresh recovery code + salt.
  const recoveryCode = generateRecoveryCode();
  const recovery = await buildRecovery(recoveryCode, vaultKey);

  const registration = {
    email: email.trim().toLowerCase(),
    kdfSalt: toBase64(kdfSalt),
    kdfParams: { ...KDF_PARAMS },
    authHash: toBase64(authHash),
    protectedVaultKey,
    vaultBlob,
    recoverySalt: recovery.recoverySalt,
    recoveryProtectedVaultKey: recovery.recoveryProtectedVaultKey,
    recoveryAuthHash: recovery.recoveryAuthHash,
  };

  return {
    registration, // -> POST /api/register
    recoveryCode, // -> show to user ONCE
    secrets: { masterKey, encKey, vaultKey }, // stay in memory only
  };
}

// Build recovery material for a given vaultKey from a recovery code.
async function buildRecovery(recoveryCode, vaultKey) {
  const recoverySalt = randomBytes(SALT_LENGTH);
  const recoveryKey = await deriveKeyFromSecret(
    normalizeRecoveryCode(recoveryCode),
    recoverySalt
  );
  const { encKey: recoveryEncKey, authHash: recoveryAuthHash } =
    await deriveSubKeys(recoveryKey, recoverySalt);
  const recoveryProtectedVaultKey = await aesGcmEncrypt(
    recoveryEncKey,
    vaultKey
  );
  return {
    recoverySalt: toBase64(recoverySalt),
    recoveryProtectedVaultKey,
    recoveryAuthHash: toBase64(recoveryAuthHash),
  };
}

// Produce the auth proof for login: derive masterKey -> authHash from MP.
export async function computeLoginAuth(masterPassword, { kdfSalt, kdfParams }) {
  const salt = fromBase64(kdfSalt);
  const masterKey = await deriveKeyFromSecret(
    masterPassword,
    salt,
    kdfParams || KDF_PARAMS
  );
  const { encKey, authHash } = await deriveSubKeys(masterKey, salt);
  return { masterKey, encKey, authHash: toBase64(authHash) };
}

// Unlock: given the server bundle, derive keys, unwrap vaultKey, decrypt blob.
// `serverBundle` = { kdfSalt, kdfParams, protectedVaultKey, vaultBlob }.
export async function unlock(masterPassword, serverBundle) {
  const { encKey } = await computeLoginAuth(masterPassword, serverBundle);
  const vaultKey = await aesGcmDecrypt(
    encKey,
    serverBundle.protectedVaultKey
  ); // GCM auth error here == wrong password
  const items = await decryptJson(vaultKey, serverBundle.vaultBlob);
  return { encKey, vaultKey, items };
}

// Re-encrypt the items array under an existing vaultKey (for save).
export async function sealVault(vaultKey, items) {
  return encryptJson(vaultKey, items);
}

// Password change: re-derive from new MP + new salt, re-wrap the SAME vaultKey.
// Vault blob is NOT re-encrypted. Returns the three fields to upload.
export async function changePassword(newMasterPassword, vaultKey) {
  const kdfSalt = randomBytes(SALT_LENGTH);
  const masterKey = await deriveKeyFromSecret(newMasterPassword, kdfSalt);
  const { encKey, authHash } = await deriveSubKeys(masterKey, kdfSalt);
  const protectedVaultKey = await aesGcmEncrypt(encKey, vaultKey);
  return {
    kdfSalt: toBase64(kdfSalt),
    kdfParams: { ...KDF_PARAMS },
    authHash: toBase64(authHash),
    protectedVaultKey,
    secrets: { masterKey, encKey },
  };
}

// Regenerate recovery for an existing vaultKey (settings -> regenerate code).
export async function regenerateRecovery(vaultKey) {
  const recoveryCode = generateRecoveryCode();
  const recovery = await buildRecovery(recoveryCode, vaultKey);
  return { recoveryCode, recovery };
}

// Recovery: unwrap the vaultKey using the recovery code, then set a new MP.
// `recoverBundle` = { recoverySalt, kdfParams?, recoveryProtectedVaultKey }.
export async function recoverWithCode(recoveryCode, recoverBundle) {
  const salt = fromBase64(recoverBundle.recoverySalt);
  const recoveryKey = await deriveKeyFromSecret(
    normalizeRecoveryCode(recoveryCode),
    salt,
    recoverBundle.kdfParams || KDF_PARAMS
  );
  const { encKey: recoveryEncKey, authHash: recoveryAuthHash } =
    await deriveSubKeys(recoveryKey, salt);
  const vaultKey = await aesGcmDecrypt(
    recoveryEncKey,
    recoverBundle.recoveryProtectedVaultKey
  ); // GCM auth error == wrong recovery code
  return { vaultKey, recoveryAuthHash: toBase64(recoveryAuthHash) };
}

// Build the POST /api/recover payload: prove with the recovery code, set new MP.
export async function buildRecoverySubmit(
  recoveryCode,
  recoverBundle,
  newMasterPassword
) {
  const { vaultKey, recoveryAuthHash } = await recoverWithCode(
    recoveryCode,
    recoverBundle
  );
  const newKdfSalt = randomBytes(SALT_LENGTH);
  const masterKey = await deriveKeyFromSecret(newMasterPassword, newKdfSalt);
  const { encKey, authHash } = await deriveSubKeys(masterKey, newKdfSalt);
  const newProtectedVaultKey = await aesGcmEncrypt(encKey, vaultKey);
  return {
    submit: {
      recoveryAuthHash,
      newKdfSalt: toBase64(newKdfSalt),
      newAuthHash: toBase64(authHash),
      newProtectedVaultKey,
    },
    secrets: { vaultKey, masterKey, encKey },
  };
}

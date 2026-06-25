# PassVault browser extension (Manifest V3)

The extension popup **is** the shared `vault-web` UI, so the unlock flow, vault
list, copy buttons, and 3-minute auto-lock behave exactly like the web app. All
encryption/decryption happens locally in the popup; the extension never stores
the master key or the decrypted vault.

## Build

```bash
bash extension/build.sh
```

This produces:

- `extension/dist/passvault-extension/` — the unpacked extension
- `extension/dist/passvault-extension.zip` — for handing to colleagues

`build.sh` copies `crypto/` and `vault-web/` verbatim into the package, swaps in
`config.ext.js` (which sets `apiBase` to the production backend), and links
`popup.css` (explicit popup width/height — an MV3 popup has no viewport to size
against, so without it the layout collapses to a thin strip). Both the config
swap and the `popup.css` link are applied only to the packaged copy; the repo's
`vault-web/` stays untouched so the Mini App (M6) keeps its full-width layout.
`dist/` is git-ignored.

## Load it (internal sideloading)

1. Open `chrome://extensions`
2. Toggle **Developer mode** (top-right)
3. **Load unpacked** → select `extension/dist/passvault-extension`

To distribute, share the `.zip`; each colleague unzips and loads the folder the
same way. (No Chrome Web Store submission — out of scope.)

## How it talks to the backend

The popup is `chrome-extension://…` (a different origin from the API). Rather
than widen the server's CORS allow-list to a per-install extension id, the
manifest declares `host_permissions: ["https://example.com/*"]`, which grants
the extension privileged cross-origin `fetch` to the API. No backend change is
required. The CSP also allows `'wasm-unsafe-eval'` so the Argon2id WASM module
can instantiate.

## Permissions (minimal, per spec)

- `storage` — non-secret settings only.
- `clipboardWrite` — copy username/password to the clipboard.
- `host_permissions: https://example.com/*` — reach the API.

No `activeTab`, no content scripts: **autofill is intentionally not shipped**.
The spec says to ship clipboard-only rather than leave autofill half-working; if
autofill is added later it would introduce `activeTab` + a content script.

## Known limitation — clipboard auto-clear

While the popup is open, a copied credential is cleared from the clipboard after
30 s (`clipboardClearMs`). If you **close the popup** before that timer fires,
the timer dies with the popup's page context and the clipboard is not auto-
cleared. Clearing the clipboard from a closed popup would require an MV3 service
worker + offscreen document; that is deliberately out of the clipboard-only
baseline. Until then: paste where you need it, then close the popup.

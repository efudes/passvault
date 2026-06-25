// Telegram Mini App bootstrap (M6).
//
// This file is loaded by index.html in ALL contexts (browser extension popup,
// plain browser tab, and the Telegram WebView), but it only does anything when
// the page was actually launched from Telegram. Detection happens BEFORE we
// fetch anything, so the extension and ordinary browsers never contact
// telegram.org and never trip the extension's strict CSP.
//
// When inside Telegram it injects the official telegram-web-app.js (which the
// server CSP allows from https://telegram.org), then calls ready()/expand() and
// makes a best-effort, non-blocking call to /api/tg/verify so the server can
// confirm the launch is genuine. That verification is a convenience /
// anti-embedding signal ONLY — the real auth is still email + master password
// (zero-knowledge), so a failure here never blocks using the vault.
(function () {
  "use strict";

  function launchedFromTelegram() {
    try {
      return (
        /tgWebApp/.test(location.hash) ||
        /tgWebApp/.test(location.search) ||
        typeof window.TelegramWebviewProxy !== "undefined"
      );
    } catch (_) {
      return false;
    }
  }

  // Expose the launch context so the rest of the UI (app.js) can reuse this same
  // signal — e.g. to hide the "download extension / open bot" corner links that
  // are meaningless inside the Telegram Mini App.
  window.PASSVAULT_IN_TELEGRAM = launchedFromTelegram();

  if (!window.PASSVAULT_IN_TELEGRAM) return; // browser / extension: do nothing.

  function onReady() {
    var wa = window.Telegram && window.Telegram.WebApp;
    if (!wa) return;
    try {
      wa.ready();
      wa.expand();
    } catch (_) {}
    // Best-effort genuineness check. Same-origin (Mini App served from DOMAIN),
    // so it works under connect-src 'self'. We deliberately ignore the result
    // for control flow; it never gates the vault.
    try {
      var initData = wa.initData || "";
      if (initData) {
        var base =
          (window.PASSVAULT_CONFIG && window.PASSVAULT_CONFIG.apiBase) || "";
        fetch(base + "/api/tg/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ initData: initData }),
        })
          .then(function (r) {
            if (!r.ok) console.debug("tg verify: not confirmed (" + r.status + ")");
          })
          .catch(function () {});
      }
    } catch (_) {}
  }

  var s = document.createElement("script");
  s.src = "https://telegram.org/js/telegram-web-app.js";
  s.async = false; // preserve order; load as soon as possible
  s.onload = onReady;
  s.onerror = function () {
    // SDK unreachable: the vault still works as a plain web app over HTTPS.
    console.debug("tg sdk failed to load; continuing as web app");
  };
  (document.head || document.documentElement).appendChild(s);
})();

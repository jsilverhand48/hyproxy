/* hyproxy IdP retro chrome -- served same-origin (script-src 'self').
   Drives the fake "visitor counter" in the footer. No network calls; the
   count is a bit of nostalgic theatre persisted in localStorage. */
(function () {
  "use strict";

  function pad(n, width) {
    var s = String(n);
    while (s.length < width) s = "0" + s;
    return s;
  }

  function bumpCounter() {
    var el = document.getElementById("visitor-counter");
    if (!el) return;
    var base = 133742; // vanity seed
    var n;
    try {
      n = parseInt(window.localStorage.getItem("hyproxy_visits") || "0", 10);
      if (!isFinite(n) || n < 0) n = 0;
      n += 1;
      window.localStorage.setItem("hyproxy_visits", String(n));
    } catch (e) {
      // localStorage blocked (private mode, etc.) -- just show the seed.
      n = 0;
    }
    el.textContent = pad(base + n, 7);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bumpCounter);
  } else {
    bumpCounter();
  }
})();

/* Dev-Buddy local injector (opt-in with ?devbuddy=1) */
(function () {
  "use strict";

  function enabledByQuery() {
    try {
      var params = new URLSearchParams(window.location.search || "");
      var flag = String(params.get("devbuddy") || "").toLowerCase();
      return flag === "1" || flag === "true" || flag === "on";
    } catch (_err) {
      return false;
    }
  }

  function isLocalHost() {
    var host = String(window.location.hostname || "").toLowerCase();
    return host === "localhost" || host === "127.0.0.1";
  }

  function appendLoader(src) {
    return new Promise(function (resolve, reject) {
      var script = document.createElement("script");
      script.src = src;
      script.async = true;
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }

  async function injectWithFallback() {
    var candidates = [
      "http://127.0.0.1:8081/dev-buddy-loader.js",
      "http://localhost:8081/dev-buddy-loader.js",
      "http://127.0.0.1:8080/dev-buddy-loader.js",
      "http://localhost:8080/dev-buddy-loader.js",
    ];
    for (var i = 0; i < candidates.length; i += 1) {
      try {
        await appendLoader(candidates[i]);
        console.info("[DevBuddyInject] Loader injected from:", candidates[i]);
        return;
      } catch (_err) {
        // try the next candidate
      }
    }
    console.warn(
      "[DevBuddyInject] Could not load Dev-Buddy. Make sure sev-buggi is running on port 8081."
    );
  }

  if (!enabledByQuery()) return;
  if (!isLocalHost()) {
    console.warn("[DevBuddyInject] Injection is allowed only on localhost/127.0.0.1.");
    return;
  }
  if (window.location.protocol !== "http:") {
    console.warn("[DevBuddyInject] Use http://localhost for local injection tests.");
    return;
  }

  injectWithFallback();
})();

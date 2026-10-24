// TOTP request pipeline (isolated world).
//
// The host returns the six digit code. The secret itself never leaves the
// host process. No DOM access here; filling the code is a later task.

(function () {
  function nonce() {
    return crypto.getRandomValues(new Uint32Array(1))[0];
  }

  window.__lengsuoSecret = {
    getTotp({ ref } = {}) {
      return chrome.runtime.sendMessage({
        kind: 'host_call',
        type: 2,
        payload: { ref: ref ?? null, nonce: nonce(), origin: location.origin },
        origin: location.origin,
      });
    },
  };
})();

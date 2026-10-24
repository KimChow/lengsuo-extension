// Password request pipeline (isolated world).
//
// Builds the §5.3.1 request and hands it to the background worker. No DOM
// access and no autofill: that is a later task. The origin is this content
// script's own, which the page cannot forge.
//
// The host returns the result; it never returns a password it does not mean to
// hand to this origin, and the policy gate in the worker decides that.

(function () {
  function nonce() {
    return crypto.getRandomValues(new Uint32Array(1))[0];
  }

  function call(type, payload) {
    return chrome.runtime.sendMessage({
      kind: 'host_call',
      type,
      payload: { ...payload, nonce: nonce(), origin: location.origin },
      origin: location.origin,
    });
  }

  window.__lengsuoPwd = {
    list() {
      return call(0, {});
    },
    getPassword({ username } = {}) {
      return call(1, { username: username ?? null });
    },
    savePassword({ username, password } = {}) {
      return call(5, { username: username ?? null, password: password ?? null });
    },
  };
})();

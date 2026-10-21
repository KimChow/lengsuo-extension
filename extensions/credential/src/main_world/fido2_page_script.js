// Main world script: intercepts navigator.credentials.
//
// It wraps create and get, answers from the managed credential when the host
// has one, and otherwise falls through to the browser's own implementation.
// Falling through is what keeps a page usable when the host is missing.

(function () {
  const CHANNEL = 'lengsuo-fido2';
  const NATIVE = [navigator.credentials.create, navigator.credentials.get];

  function post(type, payload) {
    return new Promise((resolve) => {
      const id = Math.random().toString(36).slice(2);
      const onMessage = (event) => {
        if (event.source !== window) return;
        const data = event.data;
        if (!data || data.channel !== CHANNEL || data.id !== id) return;
        window.removeEventListener('message', onMessage);
        resolve(data.result);
      };
      window.addEventListener('message', onMessage);
      window.postMessage({ channel: CHANNEL, id, type, payload }, '*');
    });
  }

  async function proxy(native, type, args) {
    let result;
    try {
      result = await post(type, args[0] ?? null);
    } catch {
      result = null;
    }
    if (!result || result.ok !== true) return native.apply(navigator.credentials, args);
    if (result.use_native === true) return native.apply(navigator.credentials, args);
    return result.value ?? null;
  }

  navigator.credentials.create = function (...args) {
    return proxy(NATIVE[0], 3, args);
  };
  navigator.credentials.get = function (...args) {
    return proxy(NATIVE[1], 4, args);
  };
})();

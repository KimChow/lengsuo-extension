// TOTP fill: the DOM half only.
//
// The host returns the six digit code. The secret itself never leaves the
// host process.

(function () {
  const CHANNEL = 'lengsuo-fido2';

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL) return;

    chrome.runtime.sendMessage({ kind: 'host_call', type: 2, payload: data.payload })
      .then((result) => {
        window.postMessage({ channel: CHANNEL, id: data.id, result }, '*');
      });
  });
})();

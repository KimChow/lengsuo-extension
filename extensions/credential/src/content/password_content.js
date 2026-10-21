// Password fill: the DOM half only.
//
// The rules come from the policy service; this script only locates the form
// and sets the values. It never decides on its own that a page may be filled.

(function () {
  const CHANNEL = 'lengsuo-fido2';

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL) return;

    chrome.runtime.sendMessage({ kind: 'policy_check', url: location.href })
      .then((decision) => {
        if (!decision || !decision.allowed) {
          window.postMessage({ channel: CHANNEL, id: data.id, result: { ok: false, reason: 'not_allowed' } }, '*');
          return;
        }
        window.postMessage({ channel: CHANNEL, id: data.id, result: { ok: true } }, '*');
      });
  });
})();

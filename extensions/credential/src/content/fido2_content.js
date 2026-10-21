// Bridge between the page's main world and the isolated world.
//
// The page script runs in the main world and cannot see extension APIs, so
// it posts messages here; this script relays them to the background worker
// and posts the answer back.

(function () {
  const CHANNEL = 'lengsuo-fido2';

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL) return;

    chrome.runtime.sendMessage({ kind: 'host_call', type: data.type, payload: data.payload })
      .then((result) => {
        window.postMessage({ channel: CHANNEL, id: data.id, result }, '*');
      })
      .catch((err) => {
        window.postMessage(
          { channel: CHANNEL, id: data.id, result: { ok: false, reason: String(err) } },
          '*',
        );
      });
  });
})();

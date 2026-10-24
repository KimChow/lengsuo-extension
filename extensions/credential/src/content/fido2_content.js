// Bridge between the page's main world and the isolated world.
//
// The page script runs in the main world and cannot see extension APIs, so
// it posts messages here; this script relays them to the background worker
// and posts the answer back.
//
// The origin is taken from this content script's own document, never from the
// page message. Content scripts live in an isolated world, so a page script
// cannot rewrite `location.origin` here; trusting the page's copy would let it
// claim any domain it likes at the policy gate.

(function () {
  const CHANNEL = 'lengsuo-fido2';

  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.channel !== CHANNEL) return;

    chrome.runtime.sendMessage({
      kind: 'host_call',
      type: data.type,
      payload: data.payload,
      origin: location.origin,
    })
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

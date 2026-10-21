// The bridge to the local host program over Chrome Native Messaging.
//
// Chrome finds the host by name in the registry, then starts it and speaks
// over stdin/stdout. No port is opened and no token is exchanged.
//
// The host name is a cross-repo constant; see
// lengsuo-browser/docs/credential-wire-contract.md §5.0.

export const HOST_NAME = 'lengsuo.credential';

// Message types, matching the frozen protocol table.
export const MSG = {
  LIST_CREDENTIALS: 0,
  GET_PASSWORD: 1,
  GET_TOTP: 2,
  PASSKEY_CREATE: 3,
  PASSKEY_GET: 4,
  SAVE_PASSWORD: 5,
  RISK_CHECK: 6,
  REVOKE_PASSKEY_REF: 7,
  RECOVER: 8,
  AUTH_QUERY: 9,
  // The host may answer with the browser's own response instead of a managed
  // one. This is the fallback path: the page still logs in.
  USE_NATIVE_RESPONSE: 10,
};

/**
 * Connect to the local host, or resolve to null when it is not installed.
 *
 * A missing host is a configuration failure, not a transient error: the
 * caller must surface it instead of silently degrading.
 */
export function connectHost() {
  return new Promise((resolve) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST_NAME);
    } catch (err) {
      resolve({ ok: false, reason: 'host_missing', detail: String(err) });
      return;
    }

    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    port.onMessage.addListener((message) => {
      finish({ ok: true, message });
    });

    port.onDisconnect.addListener(() => {
      finish({ ok: false, reason: 'host_disconnected' });
    });

    // The request frame: 4-byte big-endian length, 1-byte type,
    // 3 reserved bytes that must be zero, then the payload.
    port.postMessage({
      type: MSG.LIST_CREDENTIALS,
      payload: { nonce: newNonce() },
    });
  });
}

/** A one-shot nonce, so a replayed request is recognisable. */
export function newNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

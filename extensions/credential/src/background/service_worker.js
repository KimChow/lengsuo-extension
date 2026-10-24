// Background service worker.
//
// It owns the channel to the local host and the policy cache. Content
// scripts never talk to the host directly.

import { BridgeError, MSG, createBridge } from './native_bridge.js';
import { isAllowed, isStale } from './policy.js';

const POLICY_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * The production port factory is wrapped in an arrow so `chrome` is only
 * looked up when the first request is made. Importing this module in a Node
 * test must not need a browser global.
 */
const bridge = createBridge({
  connectNative: (name) => chrome.runtime.connectNative(name),
});

/** @type {{policy: object|null, fetchedAtMs: number}} */
let policyCache = { policy: null, fetchedAtMs: 0 };

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handle(message, sender && sender.url)
    .then((result) => sendResponse(result))
    .catch((err) => sendResponse({ ok: false, reason: 'internal', detail: String(err) }));
  // Keep the channel open for the async reply.
  return true;
});

async function handle(message, senderUrl) {
  switch (message && message.kind) {
    case 'policy_check':
      return policyCheck(message.url);
    case 'host_call': {
      // The policy gate comes first. A denied origin must not cause a single
      // byte to be written to the host, so hostCall is never reached below.
      const verdict = await policyCheck(senderUrl || message.origin || '');
      if (!verdict.allowed) return { ok: false, reason: 'policy_denied' };
      return hostCall(message.type, message.payload);
    }
    default:
      return { ok: false, reason: 'unknown_kind' };
  }
}

/**
 * Ask the policy service whether a URL may be filled.
 *
 * Every failure path returns "not allowed". A fill that happens without a
 * policy is a credential handed to a page that should not have it.
 */
async function policyCheck(url) {
  const now = Date.now();
  const cached = policyCache.policy;
  if (cached && !isStale({ ...cached, now_ms: policyCache.fetchedAtMs }, now, POLICY_MAX_AGE_MS)) {
    return { ok: true, allowed: isAllowed(url, cached) };
  }

  try {
    const response = await fetch('/api/policy/credential-domains', { method: 'GET' });
    if (!response.ok) return { ok: true, allowed: false };
    const policy = await response.json();
    policyCache = { policy, fetchedAtMs: now };
    return { ok: true, allowed: isAllowed(url, policy) };
  } catch {
    // Unreachable policy service means no fill, not a free pass.
    return { ok: true, allowed: false };
  }
}

/**
 * Forward a request to the local host.
 *
 * The payload is a §5.3.1 JSON object; the bridge wants bytes, so it is
 * encoded here. Handing the object straight to `bridge.request` throws
 * `bad_frame` and would silently disable the whole managed path.
 *
 * The host answers with a typed message. A `USE_NATIVE_RESPONSE` answer means
 * the caller should fall back to the browser's own credential handling, not
 * treat the call as a failure. Anything else that is not a valid reply is a
 * failure with the bridge's error code; payload bytes are passed through
 * untouched.
 *
 * `bridgeImpl` exists so tests can inject a fake; production never passes it.
 */
async function hostCall(type, payload, bridgeImpl = bridge) {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, reason: 'bad_payload' };
  }

  try {
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    const reply = await bridgeImpl.request(type, bytes);
    if (reply.type === MSG.USE_NATIVE_RESPONSE) {
      return { ok: true, use_native: true };
    }
    return { ok: true, use_native: false, type: reply.type, payload: reply.payload };
  } catch (err) {
    if (err instanceof BridgeError) {
      return { ok: false, reason: err.code, detail: err.detail };
    }
    return { ok: false, reason: 'internal', detail: String(err) };
  }
}

export { handle, policyCheck, hostCall };

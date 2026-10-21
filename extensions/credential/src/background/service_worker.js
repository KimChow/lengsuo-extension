// Background service worker.
//
// It owns the channel to the local host and the policy cache. Content
// scripts never talk to the host directly.

import { connectHost, MSG, newNonce } from './native_bridge.js';
import { isAllowed, isStale } from './policy.js';

const POLICY_MAX_AGE_MS = 5 * 60 * 1000;

/** @type {{policy: object|null, fetchedAtMs: number}} */
let policyCache = { policy: null, fetchedAtMs: 0 };

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handle(message)
    .then((result) => sendResponse(result))
    .catch((err) => sendResponse({ ok: false, reason: 'internal', detail: String(err) }));
  // Keep the channel open for the async reply.
  return true;
});

async function handle(message) {
  switch (message && message.kind) {
    case 'policy_check':
      return policyCheck(message.url);
    case 'host_call':
      return hostCall(message.type, message.payload);
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
 * The host answers with a typed message. A `USE_NATIVE_RESPONSE` answer means
 * the caller should fall back to the browser's own credential handling.
 */
async function hostCall(type, payload) {
  const result = await connectHost();
  if (!result.ok) return result;

  const message = result.message;
  if (!message || message.type === undefined) {
    return { ok: false, reason: 'bad_host_response' };
  }
  if (message.type === MSG.USE_NATIVE_RESPONSE) {
    return { ok: true, use_native: true };
  }
  return { ok: true, use_native: false, payload: message.payload ?? null };
}

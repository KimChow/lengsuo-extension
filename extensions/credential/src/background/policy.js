// Domain allow-list policy.
//
// The default is "nothing is allowed". A site is filled only when the policy
// service says so. Anything else -- a failed fetch, a stale cache, a miss --
// means no fill. Automatic filling hands a credential to a page, so "policy
// unavailable" must never mean "policy satisfied".
//
// The shape mirrors the reference implementation's `domain_check_list`:
// an enable list and a disable list, where the disable list starts with "*".

export const DEFAULT_POLICY = Object.freeze({
  enable: Object.freeze([]),
  disable: Object.freeze(['*']),
});

/**
 * Decide whether a URL may be filled.
 *
 * Deny wins. The account-level rule is about which credential belongs to
 * whom, not about permission, so it does not take part in this decision.
 */
export function isAllowed(url, policy) {
  const p = policy && typeof policy === 'object' ? policy : DEFAULT_POLICY;
  const enable = Array.isArray(p.enable) ? p.enable : [];
  const disable = Array.isArray(p.disable) ? p.disable : ['*'];

  const host = hostOf(url);
  if (!host) return false;

  if (matchesAny(host, disable)) return false;
  return matchesAny(host, enable);
}

/**
 * A policy is stale once it is older than its max age. A stale policy is
 * treated as "not allowed", for the same reason a missing one is.
 */
export function isStale(policy, nowMs, maxAgeMs) {
  if (!policy || typeof policy.now_ms !== 'number') return true;
  if (typeof maxAgeMs !== 'number') return false;
  return nowMs - policy.now_ms > maxAgeMs;
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function matchesAny(host, patterns) {
  for (const pattern of patterns) {
    if (typeof pattern !== 'string' || pattern.length === 0) continue;
    if (pattern === '*') return true;
    if (host === pattern) return true;
    if (host.endsWith('.' + pattern)) return true;
  }
  return false;
}

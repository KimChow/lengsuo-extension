// Fill script package format validation + scope matching.
//
// Pure functions. validatePackage checks the structural rules of a
// .lengsuopkg package (format, version, signer, scope, actions) and returns
// {ok:true} or {ok:false, reason}. scopeMatches decides whether a package
// scope applies to a given hostname.
//
// ⚠ 每条改动必须同步更新 content/fill_script_content.js 的内联实现。

import { BUILTIN_PUBLIC_KEY_B64URL } from './verify.js';

const ACTIONS = new Set(['set_value', 'click', 'wait', 'read_text', 'fill_credentials']);
const VALUE_REFS = new Set(['username', 'password', 'totp']);

export function validatePackage(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return { ok: false, reason: 'bad_format' };
  }
  if (obj.format !== 'lengsuo-fill-script' || obj.format_version !== 1) {
    return { ok: false, reason: 'bad_format' };
  }

  const sig = obj.signature;
  if (!sig || typeof sig.public_key_b64url !== 'string') {
    return { ok: false, reason: 'unknown_signer' };
  }
  if (sig.public_key_b64url !== BUILTIN_PUBLIC_KEY_B64URL) {
    return { ok: false, reason: 'unknown_signer' };
  }

  const scope = obj.scope;
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
    return { ok: false, reason: 'bad_scope' };
  }
  const suffixes = scope.domain_suffixes;
  if (!Array.isArray(suffixes) || suffixes.length === 0) {
    return { ok: false, reason: 'bad_scope' };
  }
  for (const suffix of suffixes) {
    if (typeof suffix !== 'string' || !isValidSuffix(suffix)) {
      return { ok: false, reason: 'bad_scope' };
    }
  }
  if (typeof scope.match_subdomains !== 'boolean') {
    return { ok: false, reason: 'bad_scope' };
  }

  const actions = obj.actions;
  if (!Array.isArray(actions) || actions.length === 0) {
    return { ok: false, reason: 'bad_actions' };
  }
  for (const action of actions) {
    const result = validateAction(action);
    if (!result.ok) return result;
  }

  return { ok: true };
}

// 每项以 '.' 或直接主机段起始。格式合理性：非空、不含空格、不以 '.' 结尾。
function isValidSuffix(suffix) {
  if (suffix.length === 0) return false;
  if (suffix.startsWith('.')) return suffix.length > 1 && !suffix.endsWith('.');
  return /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(suffix);
}

function validateAction(action) {
  if (!action || typeof action !== 'object' || Array.isArray(action)) {
    return { ok: false, reason: 'unknown_action' };
  }
  const name = action.action;
  if (typeof name !== 'string' || !ACTIONS.has(name)) {
    return { ok: false, reason: 'unknown_action' };
  }

  switch (name) {
    case 'set_value': {
      if (typeof action.selector !== 'string' || action.selector.length === 0) {
        return { ok: false, reason: 'bad_set_value' };
      }
      // value_ref 是凭据占位符；⛔ 禁止包内携带明文字面量。
      if (typeof action.value_ref !== 'string' || !VALUE_REFS.has(action.value_ref)) {
        return { ok: false, reason: 'bad_value_ref' };
      }
      if ('value' in action) {
        return { ok: false, reason: 'bad_value_ref' };
      }
      return { ok: true };
    }
    case 'click': {
      if (typeof action.selector !== 'string' || action.selector.length === 0) {
        return { ok: false, reason: 'bad_click' };
      }
      return { ok: true };
    }
    case 'wait': {
      const ms = action.ms;
      if (typeof ms !== 'number' || !Number.isInteger(ms) || ms < 0 || ms > 5000) {
        return { ok: false, reason: 'bad_wait' };
      }
      return { ok: true };
    }
    case 'read_text': {
      if (typeof action.selector !== 'string' || action.selector.length === 0) {
        return { ok: false, reason: 'bad_read_text' };
      }
      return { ok: true };
    }
    case 'fill_credentials': {
      const fields = action.fields;
      if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
        return { ok: false, reason: 'bad_fill_credentials' };
      }
      for (const key of ['username', 'password']) {
        if (typeof fields[key] !== 'string' || fields[key].length === 0) {
          return { ok: false, reason: 'bad_fill_credentials' };
        }
      }
      return { ok: true };
    }
    default:
      return { ok: false, reason: 'unknown_action' };
  }
}

export function scopeMatches(scope, hostname) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) return false;
  const suffixes = scope.domain_suffixes;
  if (!Array.isArray(suffixes) || suffixes.length === 0) return false;
  if (typeof scope.match_subdomains !== 'boolean') return false;
  if (typeof hostname !== 'string' || hostname.length === 0) return false;

  for (const suffix of suffixes) {
    if (typeof suffix !== 'string') continue;
    if (hostname === suffix) return true;
    if (scope.match_subdomains && hostname.endsWith('.' + suffix)) return true;
  }
  return false;
}
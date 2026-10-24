// Fill script content script (MV3 classic script, no imports).
//
// Self-contained IIFE: inlines the JCS normalization, scope matching,
// Ed25519 verification (WebCrypto), action interpreter and audit record so it
// can run without ESM imports. Behavior mirrors
// extensions/credential/src/autofill/fill_scripts/{normalize,verify,schema,
// engine,audit}.js exactly; both sides are pinned to the same fixed vectors
// in fill_scripts.test.mjs.
//
// ⚠ 改 fill_scripts/* 者必改此文件：两者对同一输入输出须逐字节相同。
//
// Content script flow:
//   chrome.runtime.getURL 读打包内 .lengsuopkg → 解析 JSON → 公钥初筛
//   (公钥 ≠ 内置 ⇒ 拒绝) → JCS 规范化 → WebCrypto Ed25519 验签 → 作用域
//   匹配 location.hostname → 匹配才 runActions（DOM api 最小实现）→ audit。
//   作用域不匹配时什么都不做，不报错。
//
// 执行结果经 audit.js 同款结构记录，console 前缀 `[lengsuo-fill]`，不打凭据值。
//
// getCredential 本卡返回占位常量；真实取值管道（__lengsuoPwd/__lengsuoSecret）
// 是后续卡，这里只保留接口。

(function () {
  const BUILTIN_PUBLIC_KEY_B64URL =
    'QRSkzRfE_MdzvmNmzKy_sWp6W0NTouBch_f5R_OFu8A';

  // ---- JCS (RFC 8785) -----------------------------------------------------

  const ESCAPE = {
    0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f',
    0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\',
  };

  function normalize(value) {
    return encodeValue(value);
  }

  function encodeValue(value) {
    const type = typeof value;
    if (value === null) return 'null';
    if (type === 'boolean') return value ? 'true' : 'false';
    if (type === 'number') return encodeNumber(value);
    if (type === 'string') return encodeString(value);
    if (Array.isArray(value)) return encodeArray(value);
    if (type === 'object') return encodeObject(value);
    throw new Error('cannot normalize value of type ' + type);
  }

  function encodeNumber(n) {
    if (!Number.isFinite(n)) {
      throw new Error('cannot normalize non-finite number ' + n);
    }
    if (Object.is(n, -0)) return '0';
    return String(n);
  }

  function encodeString(s) {
    let out = '"';
    for (let i = 0; i < s.length; i += 1) {
      const ch = s.charCodeAt(i);
      const esc = ESCAPE[ch];
      if (esc !== undefined) {
        out += esc;
      } else if (ch < 0x20) {
        out += '\\u' + ch.toString(16).padStart(4, '0');
      } else {
        out += s[i];
      }
    }
    return out + '"';
  }

  function encodeArray(arr) {
    let out = '[';
    for (let i = 0; i < arr.length; i += 1) {
      if (i > 0) out += ',';
      out += encodeValue(arr[i]);
    }
    return out + ']';
  }

  function encodeObject(obj) {
    const keys = Object.keys(obj).sort();
    let out = '{';
    for (let i = 0; i < keys.length; i += 1) {
      if (i > 0) out += ',';
      out += encodeString(keys[i]) + ':' + encodeValue(obj[keys[i]]);
    }
    return out + '}';
  }

  // ---- scope matching ------------------------------------------------------

  function isValidSuffix(suffix) {
    if (suffix.length === 0) return false;
    if (suffix.startsWith('.')) return suffix.length > 1 && !suffix.endsWith('.');
    return /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(suffix);
  }

  function scopeMatches(scope, hostname) {
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

  // ---- base64url -----------------------------------------------------------

  function b64urlDecode(text) {
    if (typeof text !== 'string' || text.length === 0) {
      throw new Error('bad signature: signature_b64url must be a non-empty string');
    }
    let s = text.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4 === 1) s = 'A' + s;
    while (s.length % 4) s += '=';
    const binary = atob(s);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  }

  // ---- Ed25519 verify (WebCrypto) ------------------------------------------

  async function importRawPublicKey(raw32) {
    const prefix = new Uint8Array([
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    const der = new Uint8Array(prefix.length + raw32.length);
    der.set(prefix, 0);
    der.set(raw32, prefix.length);
    return await crypto.subtle.importKey(
      'spki', der, { name: 'Ed25519' }, true, ['verify']
    );
  }

  async function verifyEd25519(signature, publicKeyB64url, dataBytes) {
    let raw32;
    try {
      raw32 = b64urlDecode(publicKeyB64url);
    } catch {
      return false;
    }
    if (raw32.length !== 32) return false;
    let publicKey;
    try {
      publicKey = await importRawPublicKey(raw32);
    } catch {
      return false;
    }
    return await crypto.subtle.verify('Ed25519', publicKey, signature, dataBytes);
  }

  // ---- action interpreter --------------------------------------------------

  const REQUIRED_API = ['setValue', 'click', 'wait', 'readText', 'getCredential'];

  function runActions(actions, api) {
    for (const name of REQUIRED_API) {
      if (typeof api[name] !== 'function') {
        throw new Error('missing_api:' + name);
      }
    }
    const results = [];
    for (let i = 0; i < actions.length; i += 1) {
      const action = actions[i];
      const result = runOne(action, api);
      results.push({ index: i, action: action.action, ...result });
      if (result.ok === false) {
        return { ok: false, failed_at: i, results };
      }
    }
    return { ok: true, results };
  }

  function runOne(action, api) {
    switch (action.action) {
      case 'set_value': {
        const value = api.getCredential(action.value_ref);
        return api.setValue(action.selector, value);
      }
      case 'fill_credentials': {
        const fields = [];
        for (const key of Object.keys(action.fields)) {
          const step = api.setValue(action.fields[key], api.getCredential(key));
          fields.push({ field: key, ok: step.ok, reason: step.reason });
          if (step.ok === false) return { ok: false, fields };
        }
        return { ok: true, fields };
      }
      case 'click':
        return api.click(action.selector);
      case 'wait':
        return api.wait(action.ms);
      case 'read_text':
        return { ...api.readText(action.selector), selector: action.selector };
      default:
        return { ok: false, reason: 'unknown_action' };
    }
  }

  // ---- structure validation ------------------------------------------------

  const ACTIONS = new Set(['set_value', 'click', 'wait', 'read_text', 'fill_credentials']);
  const VALUE_REFS = new Set(['username', 'password', 'totp']);

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
        for (const k of ['username', 'password']) {
          if (typeof fields[k] !== 'string' || fields[k].length === 0) {
            return { ok: false, reason: 'bad_fill_credentials' };
          }
        }
        return { ok: true };
      }
      default:
        return { ok: false, reason: 'unknown_action' };
    }
  }

  function validatePackage(obj) {
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

  function stripSignature(obj) {
    const unsigned = {};
    for (const key of Object.keys(obj)) {
      if (key !== 'signature') unsigned[key] = obj[key];
    }
    return unsigned;
  }

  async function verifyPackage(obj) {
    const sig = obj && obj.signature;
    if (!sig || typeof sig.signature_b64url !== 'string') return false;
    if (typeof sig.public_key_b64url !== 'string') return false;
    let signature;
    try {
      signature = b64urlDecode(sig.signature_b64url);
    } catch {
      return false;
    }
    if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
    const data = new TextEncoder().encode(normalize(stripSignature(obj)));
    return await verifyEd25519(signature, sig.public_key_b64url, data);
  }

  // ---- audit ---------------------------------------------------------------

  function recordExecution(params) {
    const event = Object.freeze({
      timestamp: Date.now(),
      package_id: params.package_id,
      version: params.version,
      hostname: params.hostname,
      actions_total: params.actions_total,
      actions_done: params.actions_done,
      ok: params.ok,
      reason: params.reason ?? null,
    });
    console.log('[lengsuo-fill]', JSON.stringify(event));
    return event;
  }

  // ---- DOM api for content script ------------------------------------------

  function makeDomApi() {
    const getCredential = () => {
      // ⛔ 本卡不实现真实取值管道；返回占位常量供演示与测试。
      return '__lengsuo-placeholder-credential__';
    };
    function setNativeValue(element, value) {
      const proto =
        element instanceof HTMLTextAreaElement
          ? HTMLTextAreaElement.prototype
          : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value');
      if (setter && setter.set) setter.set.call(element, value);
      else element.value = value;
    }
    return {
      setValue(selector, value) {
        const element = document.querySelector(selector);
        if (!element) return { ok: false, reason: 'element_not_found' };
        setNativeValue(element, value);
        element.dispatchEvent(new Event('input', { bubbles: true }));
        element.dispatchEvent(new Event('change', { bubbles: true }));
        return { ok: true };
      },
      click(selector) {
        const element = document.querySelector(selector);
        if (!element) return { ok: false, reason: 'element_not_found' };
        element.click();
        return { ok: true };
      },
      wait(ms) {
        return new Promise((resolve) => {
          setTimeout(resolve, ms);
        });
      },
      readText(selector) {
        const element = document.querySelector(selector);
        if (!element) return { ok: false, reason: 'element_not_found' };
        return { ok: true, text: element.textContent ?? '' };
      },
      getCredential,
    };
  }

  // ---- package runner ------------------------------------------------------

  async function runPackageBytes(bytes, hostname) {
    let obj;
    try {
      obj = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      return;
    }

    const sig = obj && obj.signature;
    if (!sig || typeof sig.public_key_b64url !== 'string') {
      recordExecution({ package_id: null, version: null, hostname, actions_total: 0, actions_done: 0, ok: false, reason: 'unknown_signer' });
      return;
    }
    if (sig.public_key_b64url !== BUILTIN_PUBLIC_KEY_B64URL) {
      recordExecution({ package_id: null, version: null, hostname, actions_total: 0, actions_done: 0, ok: false, reason: 'unknown_signer' });
      return;
    }

    const vr = validatePackage(obj);
    if (!vr.ok) {
      recordExecution({
        package_id: obj.package_id, version: obj.version, hostname,
        actions_total: 0, actions_done: 0, ok: false, reason: vr.reason,
      });
      return;
    }

    const ok = await verifyPackage(obj);
    if (!ok) {
      recordExecution({
        package_id: obj.package_id, version: obj.version, hostname,
        actions_total: obj.actions.length, actions_done: 0, ok: false, reason: 'bad_signature',
      });
      return;
    }

    if (!scopeMatches(obj.scope, hostname)) return; // no-op for non-matching pages

    const api = makeDomApi();
    const result = runActions(obj.actions, api);
    recordExecution({
      package_id: obj.package_id, version: obj.version, hostname,
      actions_total: obj.actions.length, actions_done: result.results.length,
      ok: result.ok,
      reason: result.ok ? null : result.results[result.failed_at].reason,
    });
  }

  async function loadAndRun() {
    let bytes;
    try {
      const url = chrome.runtime.getURL('src/autofill/fill_scripts/packages/example-login.lengsuopkg');
      const response = await fetch(url);
      if (!response.ok) return;
      bytes = new Uint8Array(await response.arrayBuffer());
    } catch {
      return;
    }
    await runPackageBytes(bytes, location.hostname);
  }

  // ---- test hook -----------------------------------------------------------

  if (typeof globalThis.__lengsuoFillTest === 'undefined') {
    globalThis.__lengsuoFillTest = {
      normalize,
      scopeMatches,
      b64urlDecode,
      runActions,
      recordExecution,
      verifyPackage,
    };
  }

  void loadAndRun();
})();

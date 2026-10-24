// Fill script packages: JCS normalization, Ed25519 verification, package schema
// validation, action interpreter, audit record, and content-script inline
// equivalence.
//
// Fixed vectors are written out by hand: a round-trip through the
// implementation would prove nothing.
//
// The test embeds a FIXED Ed25519 test key pair (raw 32-byte seed, hex). It is
// NOT the built-in dev key pinned in verify.js; it is only used to construct
// good/bad signatures for testing the crypto path. The built-in key is what
// schema/content-script trust in production.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as crypto from 'node:crypto';

import * as normalizeModule from '../src/autofill/fill_scripts/normalize.js';
import * as verifyModule from '../src/autofill/fill_scripts/verify.js';
import * as schemaModule from '../src/autofill/fill_scripts/schema.js';
import * as engineModule from '../src/autofill/fill_scripts/engine.js';
import * as auditModule from '../src/autofill/fill_scripts/audit.js';

const { normalize } = normalizeModule;
const { verifyPackage, BUILTIN_PUBLIC_KEY_B64URL } = verifyModule;
const { validatePackage, scopeMatches } = schemaModule;
const { runActions } = engineModule;
const { recordExecution } = auditModule;

const EXT = dirname(dirname(fileURLToPath(import.meta.url)));
const SRC = readFileSync(join(EXT, 'src', 'content', 'fill_script_content.js'), 'utf8');
const PKG_PATH = join(EXT, 'src', 'autofill', 'fill_scripts', 'packages', 'example-login.lengsuopkg');

// ---- fixed test key pair (embedded, hex) ----

const TEST_PRIV_SEED_HEX =
  'f0569622797fb92f3f35d6443130ce2ec03b94d1aa82ecd952cf63d145e12650';
const TEST_PUB_RAW_HEX =
  '2a4636d3b236eabcc510335f8e3683b3439f395a16535417cc7ec85e80fa9ba8';
const TEST_PUB_B64URL =
  'KkY207I26rzFEDNfjjaDs0OfOVoWU1QXzH7IXoD6m6g';

function makePrivateKey(seedHex) {
  const seed = Buffer.from(seedHex, 'hex');
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    seed,
  ]);
  return crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
}

function b64url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function b64urlDecode(text) {
  let s = text.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

const PRIV_KEY = makePrivateKey(TEST_PRIV_SEED_HEX);

const BASE_PKG_WITHOUT_SIG = {
  format: 'lengsuo-fill-script',
  format_version: 1,
  package_id: 'example-login',
  publisher: 'lengsuo-official',
  platform_id: 'example-login',
  version: '1.0.0',
  scope: { domain_suffixes: ['example-login.test'], match_subdomains: true },
  actions: [
    { action: 'set_value', selector: '#username', value_ref: 'username' },
    { action: 'set_value', selector: '#password', value_ref: 'password' },
    { action: 'click', selector: '#login-btn' },
    { action: 'wait', ms: 100 },
  ],
};

function makeSignedPackage(overrides = {}) {
  const pkg = { ...BASE_PKG_WITHOUT_SIG, ...overrides };
  const unsigned = { ...pkg };
  delete unsigned.signature;
  const sig = crypto.sign(null, Buffer.from(normalize(unsigned), 'utf8'), PRIV_KEY);
  pkg.signature = {
    alg: 'Ed25519',
    public_key_b64url: TEST_PUB_B64URL,
    signature_b64url: b64url(sig),
  };
  return pkg;
}

// ---- JCS (RFC 8785) --------------------------------------------------------

test('JCS normalizes empty object', () => {
  assert.equal(normalize({}), '{}');
});

test('JCS sorts keys by UTF-16 code unit order ("a" < "arr" < "b" < "z")', () => {
  // Input keys: b, a, z, arr. Sorted: a, arr, b, z.
  // ("a" is a prefix of "arr", shorter is smaller; NOT "arr" before "a".)
  const input = {
    b: 2,
    a: 1,
    z: { y: "\n\"" },
    arr: [3, 1, 2],
  };
  assert.equal(
    normalize(input),
    '{"a":1,"arr":[3,1,2],"b":2,"z":{"y":"\\n\\""}}',
  );
});

test('JCS uses shortest number representation (1.0 -> 1, 1e2 -> 100, -0 -> 0)', () => {
  const input = { a: 1.0, b: 1e2, c: -0 };
  assert.equal(normalize(input), '{"a":1,"b":100,"c":0}');
});

// A package whose signature uses the BUILTIN dev public key, so
// validatePackage's signer check passes and structure validation is reached.
// validatePackage does not verify signature crypto, so the signature bytes can
// be anything.
function makeStructPkg(overrides = {}) {
  const pkg = { ...BASE_PKG_WITHOUT_SIG, ...overrides };
  if (!pkg.signature) {
    pkg.signature = {
      alg: 'Ed25519',
      public_key_b64url: BUILTIN_PUBLIC_KEY_B64URL,
      signature_b64url: 'AAAA',
    };
  }
  return pkg;
}

// ---- schema.validatePackage ------------------------------------------------

test('good structure package (builtin public key) is valid', () => {
  assert.equal(validatePackage(makeStructPkg()).ok, true);
});

test('bad format is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({ format: 'nope' })), {
    ok: false, reason: 'bad_format',
  });
});

test('bad format_version is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({ format_version: 2 })), {
    ok: false, reason: 'bad_format',
  });
});

test('unknown signer is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({
    signature: { alg: 'Ed25519', public_key_b64url: 'AAAA', signature_b64url: 'AAAA' },
  })), { ok: false, reason: 'unknown_signer' });
});

test('unknown action is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({
    actions: [{ action: 'eval', selector: 'x' }],
  })), { ok: false, reason: 'unknown_action' });
});

test('set_value with literal value instead of value_ref is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({
    actions: [{ action: 'set_value', selector: '#x', value: 'secret' }],
  })), { ok: false, reason: 'bad_value_ref' });
});

test('set_value with invalid value_ref is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({
    actions: [{ action: 'set_value', selector: '#x', value_ref: 'cookie' }],
  })), { ok: false, reason: 'bad_value_ref' });
});

test('wait ms out of range is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({
    actions: [{ action: 'wait', ms: 9999 }],
  })), { ok: false, reason: 'bad_wait' });
});

test('empty scope domain_suffixes is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({
    scope: { domain_suffixes: [], match_subdomains: true },
  })), { ok: false, reason: 'bad_scope' });
});

test('read_text without selector is rejected', () => {
  assert.deepEqual(validatePackage(makeStructPkg({
    actions: [{ action: 'read_text' }],
  })), { ok: false, reason: 'bad_read_text' });
});

// ---- scopeMatches ----------------------------------------------------------

const scopeSub = { domain_suffixes: ['example-login.test'], match_subdomains: true };
const scopeStrict = { domain_suffixes: ['example-login.test'], match_subdomains: false };

test('scopeMatches: exact match', () => {
  assert.equal(scopeMatches(scopeSub, 'example-login.test'), true);
});

test('scopeMatches: subdomain match when match_subdomains=true', () => {
  assert.equal(scopeMatches(scopeSub, 'sub.example-login.test'), true);
});

test('scopeMatches: prefix match is rejected (evil != example)', () => {
  assert.equal(scopeMatches(scopeSub, 'evilexample-login.test'), false);
});

test('scopeMatches: unrelated host is rejected', () => {
  assert.equal(scopeMatches(scopeSub, 'other.test'), false);
});

test('scopeMatches: strict mode rejects subdomain', () => {
  assert.equal(scopeMatches(scopeStrict, 'sub.example-login.test'), false);
  assert.equal(scopeMatches(scopeStrict, 'example-login.test'), true);
});

// ---- verifyPackage ----------------------------------------------------------

test('verifyPackage accepts a good signature (test key)', () => {
  const pkg = makeSignedPackage();
  assert.equal(verifyPackage(pkg), true);
});

test('verifyPackage rejects a signature with 1 bit flipped (bad_signature)', () => {
  const pkg = makeSignedPackage();
  const sigBytes = b64urlDecode(pkg.signature.signature_b64url);
  sigBytes[0] ^= 1;
  pkg.signature.signature_b64url = b64url(sigBytes);
  assert.equal(verifyPackage(pkg), false);
});

test('verifyPackage rejects crypto mismatch: builtin public key with test signature', () => {
  const pkg = makeSignedPackage();
  pkg.signature.public_key_b64url = BUILTIN_PUBLIC_KEY_B64URL;
  assert.equal(verifyPackage(pkg), false);
});

// ---- engine.runActions -----------------------------------------------------

function fakeApi(opts = {}) {
  const calls = [];
  return {
    calls,
    setValue: (selector, value) => {
      calls.push({ method: 'setValue', selector, value });
      return { ok: true };
    },
    click: (selector) => {
      calls.push({ method: 'click', selector });
      return { ok: true };
    },
    wait: (ms) => {
      calls.push({ method: 'wait', ms });
      return { ok: true };
    },
    readText: (selector) => {
      calls.push({ method: 'readText', selector });
      return { ok: true, text: 'x' };
    },
    getCredential: (ref) => {
      calls.push({ method: 'getCredential', ref });
      return ref === 'username' ? 'alice' : ref === 'password' ? 's3cret' : null;
    },
    ...opts,
  };
}

test('engine: full green sequence returns ok true', () => {
  const api = fakeApi();
  const actions = [
    { action: 'set_value', selector: '#u', value_ref: 'username' },
    { action: 'set_value', selector: '#p', value_ref: 'password' },
    { action: 'click', selector: '#btn' },
    { action: 'wait', ms: 10 },
  ];
  const result = runActions(actions, api);
  assert.equal(result.ok, true);
  assert.equal(result.results.length, 4);
  assert.equal(api.calls[0].method, 'getCredential');
});

test('engine: mid-sequence failure stops at failed_at', () => {
  const api = fakeApi();
  const actions = [
    { action: 'set_value', selector: '#u', value_ref: 'username' },
    { action: 'set_value', selector: '#missing', value_ref: 'username' },
    { action: 'set_value', selector: '#p', value_ref: 'password' },
  ];
  api.setValue = (selector) =>
    selector === '#missing' ? { ok: false, reason: 'element_not_found' } : { ok: true };
  const result = runActions(actions, api);
  assert.equal(result.ok, false);
  assert.equal(result.failed_at, 1);
  assert.equal(result.results.length, 2); // stopped, never ran step 2
});

test('engine: missing api method throws missing_api:<name>', () => {
  const api = { setValue: () => ({ ok: true }) };
  assert.throws(() => runActions([{ action: 'click', selector: '#x' }], api), /missing_api:click/);
});

test('engine: wait uses injected api.wait (no direct setTimeout)', () => {
  const api = fakeApi();
  let waitedMs = null;
  api.wait = (ms) => { waitedMs = ms; return { ok: true }; };
  const actions = [{ action: 'wait', ms: 42 }];
  const result = runActions(actions, api);
  assert.equal(result.ok, true);
  assert.equal(waitedMs, 42);
});

// ---- audit.recordExecution --------------------------------------------------

test('audit: returns a frozen immutable event without credential values', () => {
  const event = recordExecution({
    package_id: 'example-login',
    version: '1.0.0',
    hostname: 'example-login.test',
    actions_total: 4,
    actions_done: 4,
    ok: true,
    reason: null,
  });
  assert.equal(event.ok, true);
  assert.equal(event.package_id, 'example-login');
  assert.equal(event.reason, null);
  assert.throws(() => { event.ok = false; }, TypeError);
  assert.throws(() => { event.password = 's3cret'; }, TypeError);
  assert.equal(typeof event.timestamp, 'number');
});

// ---- content script inline equivalence -------------------------------------

function loadContentInline() {
  const posted = [];
  const chrome = {
    runtime: { getURL: () => 'fake://pkg' },
    _posted: posted,
  };
  globalThis.fetch = async () => ({ ok: false });
  globalThis.__lengsuoFillTest = undefined;
  const factory = new Function(
    'window', 'document', 'location', 'chrome', 'crypto', SRC,
  );
  factory(
    {
      addEventListener() {}, removeEventListener() {}, dispatchEvent() {},
      postMessage() {}, location: { hostname: 'example-login.test' },
      document: { querySelector: () => null },
      crypto: { subtle: { importKey: async () => {}, verify: async () => false } },
    },
    { querySelector: () => null },
    { hostname: 'example-login.test' },
    chrome,
    crypto,
  );
  return globalThis.__lengsuoFillTest;
}

test('content script inline: normalize matches ESM normalize', () => {
  const inline = loadContentInline();
  const input = { b: 2, a: 1, z: { y: "\n\"" }, arr: [3, 1, 2] };
  assert.equal(inline.normalize(input), normalize(input));
  assert.equal(inline.normalize({}), '{}');
  assert.equal(inline.normalize({ a: 1.0, b: 1e2, c: -0 }), '{"a":1,"b":100,"c":0}');
});

test('content script inline: scopeMatches matches ESM scopeMatches', () => {
  const inline = loadContentInline();
  const cases = [
    [{ domain_suffixes: ['example-login.test'], match_subdomains: true }, 'sub.example-login.test', true],
    [{ domain_suffixes: ['example-login.test'], match_subdomains: true }, 'evilexample-login.test', false],
    [{ domain_suffixes: ['example-login.test'], match_subdomains: false }, 'sub.example-login.test', false],
  ];
  for (const [scope, hostname, expected] of cases) {
    assert.equal(inline.scopeMatches(scope, hostname), expected);
    assert.equal(scopeMatches(scope, hostname), expected);
  }
});

test('content script inline: runActions matches ESM runActions', () => {
  const inline = loadContentInline();
  const actions = [
    { action: 'set_value', selector: '#u', value_ref: 'username' },
    { action: 'click', selector: '#btn' },
  ];
  const api = {
    setValue: () => ({ ok: true }),
    click: () => ({ ok: true }),
    wait: () => ({ ok: true }),
    readText: () => ({ ok: true, text: 'x' }),
    getCredential: () => 'alice',
  };
  const expected = runActions(actions, api);
  const actual = inline.runActions(actions, api);
  assert.deepEqual(actual, expected);
});

test('content script inline: verifyPackage matches ESM verifyPackage (crypto)', async () => {
  const inline = loadContentInline();
  const pkg = makeSignedPackage();
  const esmResult = verifyPackage(pkg);
  const inlineResult = await inline.verifyPackage(pkg);
  assert.equal(inlineResult, esmResult);

  // bad signature flips both
  const bad = makeSignedPackage();
  const sigBytes = b64urlDecode(bad.signature.signature_b64url);
  sigBytes[0] ^= 1;
  bad.signature.signature_b64url = b64url(sigBytes);
  assert.equal(await inline.verifyPackage(bad), false);
  assert.equal(verifyPackage(bad), false);
});

// ---- example package verification ------------------------------------------

test('example-login.lengsuopkg passes crypto verification (test key)', async () => {
  const bytes = readFileSync(PKG_PATH);
  const pkg = JSON.parse(new TextDecoder().decode(bytes));
  assert.equal(pkg.format, 'lengsuo-fill-script');
  assert.equal(verifyPackage(pkg), true);
});

test('example-login.lengsuopkg fails schema builtin-key check (expected for dev key)', () => {
  const bytes = readFileSync(PKG_PATH);
  const pkg = JSON.parse(new TextDecoder().decode(bytes));
  // example package is signed with the TEST key, not the builtin dev key.
  assert.equal(validatePackage(pkg).ok, false);
  assert.equal(validatePackage(pkg).reason, 'unknown_signer');
});

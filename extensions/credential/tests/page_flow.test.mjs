// The page script runs in the main world, so it cannot import anything. The
// tests execute the real source in a sandbox with browser globals supplied as
// function parameters, then drive the postMessage channel by hand.
//
// The fixed vectors below are written out by hand: a round-trip through the
// implementation would prove nothing (an encoder and decoder that share the
// same wrong bytes still agree with each other).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXT = dirname(dirname(fileURLToPath(import.meta.url)));
const SRC = readFileSync(join(EXT, 'src', 'main_world', 'fido2_page_script.js'), 'utf8');

const CHANNEL = 'lengsuo-fido2';
const ORIGIN = 'https://shop.example.test';

// ---- independent helpers (deliberately not the page script's) --------------

function b64url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

// 32 + 1 + 4 + 16 + 2 + 16 + 77 = 148 bytes, per contract §2.
const AUTH_DATA_HEX =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
  '45' +
  '00000001' +
  '00000000000000000000000000000000' +
  '0010' +
  '303132333435363738393a3b3c3d3e3f' +
  'a5010203262001215820' +
  '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' +
  '225820' +
  '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f';

// CBOR {"fmt":"none","attStmt":{},"authData":bytes(148)}, in the order §3 lists.
const ATTESTATION_HEX =
  'a3' +
  '63' + '666d74' + '64' + '6e6f6e65' +
  '67' + '61747453746d74' + 'a0' +
  '68' + '6175746844617461' + '5894' +
  AUTH_DATA_HEX;

function fromHex(text) {
  assert.equal(text.length % 2, 0);
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ---- sandbox ---------------------------------------------------------------

function makeWindow() {
  const listeners = new Set();
  const posted = [];
  const win = {
    posted,
    addEventListener(type, fn) {
      if (type === 'message') listeners.add(fn);
    },
    removeEventListener(type, fn) {
      if (type === 'message') listeners.delete(fn);
    },
    postMessage(message) {
      posted.push(message);
    },
    deliver(data) {
      for (const fn of [...listeners]) fn({ source: win, data });
    },
  };
  return win;
}

function loadPage(origin = ORIGIN, withPrototypes = true) {
  const window = makeWindow();
  const location = { origin };
  const nativeCalls = [];
  const navigator = {
    credentials: {
      create(options) {
        nativeCalls.push({ method: 'create', options });
        return 'native::create';
      },
      get(options) {
        nativeCalls.push({ method: 'get', options });
        return 'native::get';
      },
    },
  };

  class PublicKeyCredential {}
  class AuthenticatorAttestationResponse {}
  class AuthenticatorAssertionResponse {}

  // Simulate a page where the WebAuthn globals are unavailable.
  const PublicKeyCredential_ = withPrototypes ? PublicKeyCredential : undefined;
  const AuthenticatorAttestationResponse_ = withPrototypes
    ? AuthenticatorAttestationResponse
    : undefined;
  const AuthenticatorAssertionResponse_ = withPrototypes ? AuthenticatorAssertionResponse : undefined;

  const hook = {};
  globalThis.__LENGSUO_PAGE_TEST_HOOK__ = (api) => Object.assign(hook, api);
  try {
    const factory = new Function(
      'window',
      'location',
      'navigator',
      'PublicKeyCredential',
      'AuthenticatorAttestationResponse',
      'AuthenticatorAssertionResponse',
      SRC,
    );
    factory(
      window,
      location,
      navigator,
      PublicKeyCredential_,
      AuthenticatorAttestationResponse_,
      AuthenticatorAssertionResponse_,
    );
  } finally {
    delete globalThis.__LENGSUO_PAGE_TEST_HOOK__;
  }

  return {
    window,
    location,
    navigator,
    nativeCalls,
    hook,
    PublicKeyCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
  };
}

function createOptions() {
  return {
    rp: { id: 'example.test', name: 'Example' },
    user: {
      id: new Uint8Array([1, 2, 3, 4]),
      name: 'alice@example.test',
      displayName: 'Alice',
    },
    challenge: new Uint8Array(32).fill(7),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  };
}

function getOptions() {
  return {
    rpId: 'example.test',
    challenge: new Uint8Array(32).fill(9),
    allowCredentials: [
      { type: 'public-key', id: new Uint8Array([1, 2]) },
      { type: 'public-key', id: new Uint8Array([3]) },
    ],
  };
}

function clientDataFor(request, overrides = {}) {
  return {
    type: 'webauthn.create',
    challenge: request.challenge,
    origin: ORIGIN,
    ...overrides,
  };
}

function managedResult(type, response) {
  return { ok: true, use_native: false, type, payload: utf8(JSON.stringify(response)) };
}

// ---- base64url -------------------------------------------------------------

test('b64urlEncode uses the URL-safe alphabet and drops padding', () => {
  const page = loadPage();
  assert.equal(page.hook.b64urlEncode(new Uint8Array([0xfb, 0xff])), '-_8');
  assert.equal(page.hook.b64urlEncode(new Uint8Array([0x00])), 'AA');
  assert.equal(page.hook.b64urlEncode(new Uint8Array(8)), 'AAAAAAAAAAA');
  assert.equal(page.hook.b64urlEncode(new ArrayBuffer(1)), 'AA');
});

test('b64urlDecode accepts trailing padding but refuses anything else', () => {
  const page = loadPage();
  assert.deepEqual(Array.from(page.hook.b64urlDecode('-_8')), [0xfb, 0xff]);
  assert.deepEqual(Array.from(page.hook.b64urlDecode('-_8=')), [0xfb, 0xff]);
  assert.throws(() => page.hook.b64urlDecode('+/8'), /invalid/i);
  assert.throws(() => page.hook.b64urlDecode('a b'), /invalid/i);
  assert.throws(() => page.hook.b64urlDecode(''));
  assert.throws(() => page.hook.b64urlDecode(undefined));
});

// ---- request construction --------------------------------------------------

test('buildCreateRequest maps every §5.3.1 field', () => {
  const page = loadPage();
  const options = createOptions();
  const req = page.hook.buildCreateRequest(options);

  assert.ok(Number.isInteger(req.nonce));
  assert.equal(req.origin, ORIGIN);
  assert.equal(req.rp_id, 'example.test');
  assert.equal(req.challenge, b64url(options.challenge));
  assert.deepEqual(req.user, {
    id: b64url(options.user.id),
    name: 'alice@example.test',
    display_name: 'Alice',
  });
  assert.deepEqual(Object.keys(req).sort(), ['challenge', 'nonce', 'origin', 'rp_id', 'user']);
});

test('buildGetRequest maps allow_ids as base64url', () => {
  const page = loadPage();
  const options = getOptions();
  const req = page.hook.buildGetRequest(options);

  assert.ok(Number.isInteger(req.nonce));
  assert.equal(req.origin, ORIGIN);
  assert.equal(req.rp_id, 'example.test');
  assert.equal(req.challenge, b64url(options.challenge));
  assert.deepEqual(req.allow_ids, [b64url(new Uint8Array([1, 2])), b64url(new Uint8Array([3]))]);
});

test('buildGetRequest treats a missing allowCredentials list as empty', () => {
  const page = loadPage();
  const req = page.hook.buildGetRequest({
    rpId: 'example.test',
    challenge: new Uint8Array([1]),
  });
  assert.deepEqual(req.allow_ids, []);
});

// ---- wrapping --------------------------------------------------------------

test('wrapCreation emits the hand-written CBOR attestationObject', () => {
  const page = loadPage();
  const authData = fromHex(AUTH_DATA_HEX);
  const credId = new Uint8Array(16).fill(0x30);

  const response = {
    client_data_json_b64: b64url(utf8('{}')),
    auth_data_b64: b64url(authData),
    credential_id: b64url(credId),
  };

  const cred = page.hook.wrapCreation(response);

  // Fixed literal: CBOR map(3) { "fmt": "none", "attStmt": {}, "authData": bytes(148) }.
  assert.equal(hex(cred.response.attestationObject), ATTESTATION_HEX);
  assert.equal(cred.response.attestationObject.length, 178);
  assert.deepEqual(cred.response.clientDataJSON, utf8('{}'));
  assert.deepEqual(cred.response.getAuthenticatorData(), authData);
  assert.deepEqual(cred.response.getTransports(), []);
  assert.equal(cred.response.getPublicKey(), null);
  assert.equal(cred.response.getPublicKeyAlgorithm(), -7);
  assert.equal(cred.id, b64url(credId));
  assert.deepEqual(cred.rawId, credId);
  assert.equal(cred.type, 'public-key');

  assert.ok(cred instanceof page.PublicKeyCredential);
  assert.ok(cred.response instanceof page.AuthenticatorAttestationResponse);
});

test('wrapAssertion keeps signature and userHandle, and accepts no userHandle', () => {
  const page = loadPage();
  const authData = fromHex(AUTH_DATA_HEX);
  const signature = new Uint8Array([9, 9, 9]);
  const userHandle = new Uint8Array([5, 5]);

  const withUser = page.hook.wrapAssertion({
    client_data_json_b64: b64url(utf8('{}')),
    auth_data_b64: b64url(authData),
    signature_b64: b64url(signature),
    user_handle: b64url(userHandle),
  });

  assert.deepEqual(withUser.response.signature, signature);
  assert.deepEqual(withUser.response.userHandle, userHandle);
  assert.deepEqual(withUser.response.authenticatorData, authData);
  assert.ok(withUser.response instanceof page.AuthenticatorAssertionResponse);
  assert.ok(withUser instanceof page.PublicKeyCredential);

  const withoutUser = page.hook.wrapAssertion({
    client_data_json_b64: b64url(utf8('{}')),
    auth_data_b64: b64url(authData),
    signature_b64: b64url(signature),
  });
  assert.equal(withoutUser.response.userHandle, null);
});

test('wrapping skips prototype setup when the native classes are absent', () => {
  const page = loadPage(ORIGIN, false);
  // Undefined classes: the hook still returns an object instead of throwing.
  const response = {
    client_data_json_b64: b64url(utf8('{}')),
    auth_data_b64: b64url(fromHex(AUTH_DATA_HEX)),
    credential_id: b64url(new Uint8Array(16)),
  };
  assert.doesNotThrow(() => page.hook.wrapCreation(response));
});

// ---- the intercepted create/get path --------------------------------------

test('a managed create response becomes a wrapped PublicKeyCredential', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.create(createOptions());
  const sent = page.window.posted.at(-1);
  assert.equal(sent.channel, CHANNEL);
  assert.equal(sent.type, 3);

  const request = sent.payload;
  const credId = new Uint8Array(16).fill(0x30);
  const response = {
    nonce: request.nonce,
    client_data_json_b64: b64url(utf8(JSON.stringify(clientDataFor(request)))),
    auth_data_b64: b64url(fromHex(AUTH_DATA_HEX)),
    credential_id: b64url(credId),
  };
  page.window.deliver({ channel: CHANNEL, id: sent.id, result: managedResult(3, response) });

  const cred = await promise;
  assert.equal(cred.id, b64url(credId));
  assert.ok(cred instanceof page.PublicKeyCredential);
  assert.ok(cred.response instanceof page.AuthenticatorAttestationResponse);
  assert.equal(page.nativeCalls.length, 0);
});

test('a managed get response becomes a wrapped assertion credential', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.get(getOptions());
  const sent = page.window.posted.at(-1);
  assert.equal(sent.type, 4);

  const request = sent.payload;
  const signature = new Uint8Array([1, 2, 3]);
  const response = {
    nonce: request.nonce,
    client_data_json_b64: b64url(utf8(JSON.stringify({ ...clientDataFor(request), type: 'webauthn.get' }))),
    auth_data_b64: b64url(fromHex(AUTH_DATA_HEX)),
    signature_b64: b64url(signature),
    user_handle: b64url(new Uint8Array([0xaa])),
  };
  page.window.deliver({ channel: CHANNEL, id: sent.id, result: managedResult(4, response) });

  const cred = await promise;
  assert.deepEqual(cred.response.signature, signature);
  assert.ok(cred instanceof page.PublicKeyCredential);
  assert.ok(cred.response instanceof page.AuthenticatorAssertionResponse);
  assert.equal(page.nativeCalls.length, 0);
});

test('type 10 falls back to the browser native call', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.create(createOptions());
  const sent = page.window.posted.at(-1);
  page.window.deliver({ channel: CHANNEL, id: sent.id, result: { ok: true, use_native: true } });

  assert.equal(await promise, 'native::create');
  assert.equal(page.nativeCalls.length, 1);
});

test('a transport failure falls back to the browser native call', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.get(getOptions());
  const sent = page.window.posted.at(-1);
  page.window.deliver({
    channel: CHANNEL,
    id: sent.id,
    result: { ok: false, reason: 'host_missing' },
  });

  assert.equal(await promise, 'native::get');
  assert.equal(page.nativeCalls.length, 1);
});

// ---- managed-response validation (reverse anchors) -------------------------

test('a response whose origin does not match is rejected, never treated as native', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.create(createOptions());
  const sent = page.window.posted.at(-1);
  const request = sent.payload;

  const response = {
    nonce: request.nonce,
    client_data_json_b64: b64url(
      utf8(JSON.stringify(clientDataFor(request, { origin: 'https://evil.test' }))),
    ),
    auth_data_b64: b64url(fromHex(AUTH_DATA_HEX)),
    credential_id: b64url(new Uint8Array(16)),
  };
  page.window.deliver({ channel: CHANNEL, id: sent.id, result: managedResult(3, response) });

  // Anchor: deleting the origin check turns this red (it would resolve).
  await assert.rejects(promise, /origin/i);
  assert.equal(page.nativeCalls.length, 0, 'a mangled channel must not be disguised as "no credential"');
});

test('a response whose nonce does not match is rejected', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.create(createOptions());
  const sent = page.window.posted.at(-1);
  const request = sent.payload;

  const response = {
    nonce: request.nonce + 1,
    client_data_json_b64: b64url(utf8(JSON.stringify(clientDataFor(request)))),
    auth_data_b64: b64url(fromHex(AUTH_DATA_HEX)),
    credential_id: b64url(new Uint8Array(16)),
  };
  page.window.deliver({ channel: CHANNEL, id: sent.id, result: managedResult(3, response) });

  // Anchor: deleting the nonce check turns this red.
  await assert.rejects(promise, /nonce/i);
  assert.equal(page.nativeCalls.length, 0);
});

test('a response whose challenge does not match is rejected', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.get(getOptions());
  const sent = page.window.posted.at(-1);
  const request = sent.payload;

  const response = {
    nonce: request.nonce,
    client_data_json_b64: b64url(
      utf8(JSON.stringify({ ...clientDataFor(request), challenge: b64url(new Uint8Array([0])) })),
    ),
    auth_data_b64: b64url(fromHex(AUTH_DATA_HEX)),
    signature_b64: b64url(new Uint8Array([1])),
  };
  page.window.deliver({ channel: CHANNEL, id: sent.id, result: managedResult(4, response) });

  await assert.rejects(promise, /challenge/i);
  assert.equal(page.nativeCalls.length, 0);
});

test('a structurally incomplete managed response is rejected', async () => {
  const page = loadPage();
  const promise = page.navigator.credentials.create(createOptions());
  const sent = page.window.posted.at(-1);
  const request = sent.payload;

  const response = {
    nonce: request.nonce,
    client_data_json_b64: b64url(utf8(JSON.stringify(clientDataFor(request)))),
    auth_data_b64: b64url(fromHex(AUTH_DATA_HEX)),
    // credential_id is missing.
  };
  page.window.deliver({ channel: CHANNEL, id: sent.id, result: managedResult(3, response) });

  await assert.rejects(promise);
  assert.equal(page.nativeCalls.length, 0);
});

// ---- password / TOTP entry points -----------------------------------------

test('the page exposes the password and TOTP request entry points', async () => {
  const page = loadPage();
  const api = page.window.__lengsuoCredential;
  assert.equal(typeof api.list, 'function');
  assert.equal(typeof api.getPassword, 'function');
  assert.equal(typeof api.savePassword, 'function');
  assert.equal(typeof api.getTotp, 'function');

  const promise = api.getPassword({ username: 'alice' });
  const sent = page.window.posted.at(-1);
  assert.equal(sent.channel, CHANNEL);
  assert.equal(sent.type, 1);
  assert.equal(sent.payload.origin, ORIGIN);
  assert.equal(sent.payload.username, 'alice');
  assert.ok(Number.isInteger(sent.payload.nonce));

  page.window.deliver({
    channel: CHANNEL,
    id: sent.id,
    result: { ok: true, use_native: false, type: 1, payload: utf8(JSON.stringify({ password: 's3cret' })) },
  });
  assert.deepEqual(await promise, { password: 's3cret' });
});

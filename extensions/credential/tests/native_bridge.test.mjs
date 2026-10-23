// The bridge to the local host is a byte-level contract shared with the
// Rust side. These tests pin the fixed vectors by hand rather than trusting a
// round-trip: an implementation that encodes and decodes the same wrong bytes
// would still pass a round-trip test.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  HOST_NAME,
  MSG,
  MAX_PAYLOAD_BYTES,
  BridgeError,
  encodeFrame,
  decodeFrame,
  base64Encode,
  base64Decode,
  envelopeOf,
  encodeEnvelope,
  frameOfEnvelope,
  createBridge,
  newNonce,
} from '../src/background/native_bridge.js';

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(text) {
  assert.ok(text.length % 2 === 0, 'hex literal must have an even length');
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const EMPTY = new Uint8Array(0);

// ---- constants -------------------------------------------------------------

test('the cross-repo constants are pinned', () => {
  assert.equal(HOST_NAME, 'lengsuo.credential');
  assert.equal(MAX_PAYLOAD_BYTES, 1024 * 1024);
  assert.deepEqual(MSG, {
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
    USE_NATIVE_RESPONSE: 10,
  });
  assert.ok(Object.isFrozen(MSG));
});

// ---- frame fixed vectors ---------------------------------------------------

test('encodeFrame writes the hand-computed empty frame', () => {
  // len=0 (u32 BE) | type=0a | reserved 00 00 00
  assert.equal(hex(encodeFrame(MSG.USE_NATIVE_RESPONSE, EMPTY)), '000000000a000000');
  assert.equal(encodeFrame(MSG.USE_NATIVE_RESPONSE, EMPTY).length, 8);
});

test('encodeFrame writes the hand-computed four-byte frame', () => {
  // len=4 (u32 BE) | type=00 | reserved | payload 01 02 03 04
  const frame = encodeFrame(MSG.LIST_CREDENTIALS, fromHex('01020304'));
  assert.equal(hex(frame), '000000040000000001020304');
  assert.equal(frame.length, 12);
});

test('decodeFrame returns the type and payload unchanged', () => {
  const empty = decodeFrame(fromHex('000000000a000000'));
  assert.equal(empty.type, MSG.USE_NATIVE_RESPONSE);
  assert.deepEqual(empty.payload, EMPTY);

  const withPayload = decodeFrame(fromHex('000000040000000001020304'));
  assert.equal(withPayload.type, MSG.LIST_CREDENTIALS);
  assert.deepEqual(Array.from(withPayload.payload), [1, 2, 3, 4]);
});

test('encodeFrame refuses a payload over the 1 MiB limit', () => {
  const tooBig = new Uint8Array(MAX_PAYLOAD_BYTES + 1);
  assert.throws(() => encodeFrame(MSG.SAVE_PASSWORD, tooBig), (err) => err.code === 'bad_frame');
});

// ---- frame rejection paths -------------------------------------------------

test('decodeFrame rejects a truncated header', () => {
  assert.throws(() => decodeFrame(new Uint8Array(7)), (err) => err.code === 'bad_frame');
});

test('decodeFrame rejects a non-zero reserved byte', () => {
  // reserved = 00 00 01
  assert.throws(() => decodeFrame(fromHex('000000000a000001')), (err) => err.code === 'bad_frame');
});

test('decodeFrame rejects a length over 1 MiB', () => {
  // len = 0x00100001 = 1048577 = 1 MiB + 1
  assert.throws(() => decodeFrame(fromHex('0010000100000000')), (err) => err.code === 'bad_frame');
});

test('decodeFrame rejects a trailing byte beyond the declared length', () => {
  // len = 0, but nine bytes are present
  assert.throws(() => decodeFrame(fromHex('0000000000000000ff')), (err) => err.code === 'bad_frame');
});

test('decodeFrame rejects a payload shorter than the declared length', () => {
  // len = 1, but no payload byte follows
  assert.throws(() => decodeFrame(fromHex('0000000100000000')), (err) => err.code === 'bad_frame');
});

test('decodeFrame rejects an unknown message type', () => {
  assert.throws(() => decodeFrame(fromHex('000000000b000000')), (err) => err.code === 'bad_frame');
});

// ---- base64 ---------------------------------------------------------------

test('base64Encode emits no padding', () => {
  // Eight zero bytes are 64 bits, so 11 base64 characters. The card's vector
  // has 11 'A's; the extra '=' some encoders add is deliberately absent.
  assert.equal(base64Encode(fromHex('0000000000000000')), 'AAAAAAAAAAA');
  assert.equal(base64Encode(fromHex('0000000000000000')).length, 11);
});

test('base64Decode accepts padded and unpadded input', () => {
  const zeros = fromHex('0000000000000000');
  assert.deepEqual(base64Decode('AAAAAAAAAAA'), zeros);
  assert.deepEqual(base64Decode('AAAAAAAAAAA='), zeros);
});

test('base64Decode rejects padding in the middle', () => {
  assert.throws(() => base64Decode('AAA=AAAA'), (err) => err.code === 'bad_frame');
});

test('base64Decode rejects URL-safe characters', () => {
  assert.throws(() => base64Decode('AAA-AAAA'), (err) => err.code === 'bad_frame');
  assert.throws(() => base64Decode('AAA_AAAA'), (err) => err.code === 'bad_frame');
});

test('base64Decode rejects an empty string and impossible lengths', () => {
  assert.throws(() => base64Decode(''), (err) => err.code === 'bad_frame');
  assert.throws(() => base64Decode('A'), (err) => err.code === 'bad_frame');
  assert.throws(() => base64Decode('AAAAA'), (err) => err.code === 'bad_frame');
});

// ---- JSON envelope --------------------------------------------------------
//
// Chromium stringifies whatever JS value `postMessage` receives and parses the
// reply before `onMessage` runs. So the JS side sends an *object* and reads an
// *object*; the JSON text exists only on the wire.

const ZERO_FRAME = fromHex('0000000000000000');
const ZERO_ENVELOPE = '{"frame_b64":"AAAAAAAAAAA"}';
const ZERO_VALUE = { frame_b64: 'AAAAAAAAAAA' };

test('encodeEnvelope emits the exact minimal JSON wire text', () => {
  assert.equal(encodeEnvelope(ZERO_FRAME), ZERO_ENVELOPE);
  assert.equal(encodeEnvelope(ZERO_FRAME).includes(' '), false);
});

test('envelopeOf is the object form, and stringifying it is the wire text', () => {
  assert.deepEqual(envelopeOf(ZERO_FRAME), ZERO_VALUE);
  // This equality is the whole point: Chromium does the stringify for us.
  assert.equal(JSON.stringify(envelopeOf(ZERO_FRAME)), ZERO_ENVELOPE);
});

test('frameOfEnvelope returns the frame bytes from the parsed object', () => {
  assert.deepEqual(frameOfEnvelope(ZERO_VALUE), ZERO_FRAME);
  assert.deepEqual(frameOfEnvelope({ frame_b64: 'AAAAAAAAAAA=' }), ZERO_FRAME);
});

test('frameOfEnvelope rejects a string: the peer double-encoded the envelope', () => {
  assert.throws(() => frameOfEnvelope(ZERO_ENVELOPE), (err) => err.code === 'bad_frame');
});

test('frameOfEnvelope rejects extra keys and a non-string value', () => {
  assert.throws(
    () => frameOfEnvelope({ frame_b64: 'AAAAAAAAAAA', x: 1 }),
    (err) => err.code === 'bad_frame',
  );
  assert.throws(() => frameOfEnvelope({ frame_b64: 123 }), (err) => err.code === 'bad_frame');
});

test('frameOfEnvelope rejects a missing key, an array, null, and a non-plain object', () => {
  assert.throws(() => frameOfEnvelope({}), (err) => err.code === 'bad_frame');
  assert.throws(() => frameOfEnvelope([]), (err) => err.code === 'bad_frame');
  assert.throws(() => frameOfEnvelope(null), (err) => err.code === 'bad_frame');
  class Envelope {
    constructor() {
      this.frame_b64 = 'AAAAAAAAAAA';
    }
  }
  assert.throws(() => frameOfEnvelope(new Envelope()), (err) => err.code === 'bad_frame');
});

// ---- bridge ---------------------------------------------------------------

/**
 * A fake port that behaves the way Chromium's port does, not the way a naive
 * mock does:
 *   - `postMessage` receives a JS value and JSON-stringifies it onto the wire
 *   - the listener receives a parsed value, not wire text
 */
function fakePort() {
  const sent = []; // JS values handed to postMessage
  const wire = []; // what the host reads: JSON.stringify of each value
  const messageListeners = [];
  const disconnectListeners = [];
  return {
    sent,
    wire,
    postMessage(value) {
      sent.push(value);
      wire.push(JSON.stringify(value));
    },
    onMessage: {
      addListener(fn) {
        messageListeners.push(fn);
      },
    },
    onDisconnect: {
      addListener(fn) {
        disconnectListeners.push(fn);
      },
    },
    disconnect() {
      for (const fn of disconnectListeners) fn();
    },
    // Raw delivery, for pinning what onMessage does with a given value.
    emitMessage(value) {
      for (const fn of messageListeners) fn(value);
    },
    // Normal reply: the host writes text; Chromium parses it before delivery.
    reply(text) {
      for (const fn of messageListeners) fn(JSON.parse(text));
    },
    emitDisconnect() {
      for (const fn of disconnectListeners) fn();
    },
  };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

function replyFrame(type, payload = EMPTY) {
  return encodeEnvelope(encodeFrame(type, payload));
}

// The same frame as the object Chromium would hand to onMessage.
function replyValue(type, payload = EMPTY) {
  return JSON.parse(replyFrame(type, payload));
}

test('a request posts an object carrying only frame_b64 and returns one reply', async () => {
  const port = fakePort();
  const bridge = createBridge({
    connectNative(name) {
      assert.equal(name, HOST_NAME);
      return port;
    },
  });

  const pending = bridge.request(MSG.GET_TOTP, fromHex('010203'), { timeoutMs: 200 });
  await flush();

  assert.equal(port.sent.length, 1);
  // (a) an object, not an array
  assert.equal(typeof port.sent[0], 'object');
  assert.equal(Array.isArray(port.sent[0]), false);
  // (c) exactly one key, a string value
  assert.deepEqual(Object.keys(port.sent[0]), ['frame_b64']);
  assert.equal(typeof port.sent[0].frame_b64, 'string');

  // The posted value is an envelope around exactly the frame we asked for.
  const decoded = decodeFrame(frameOfEnvelope(port.sent[0]));
  assert.equal(decoded.type, MSG.GET_TOTP);
  assert.deepEqual(Array.from(decoded.payload), [1, 2, 3]);

  port.reply(replyFrame(MSG.USE_NATIVE_RESPONSE));
  const result = await pending;
  assert.equal(result.type, MSG.USE_NATIVE_RESPONSE);
  assert.deepEqual(result.payload, EMPTY);
});

test('a type-10 empty request crosses the wire as the pinned JSON text', async () => {
  const port = fakePort();
  const bridge = createBridge({ connectNative: () => port });

  const pending = bridge.request(MSG.USE_NATIVE_RESPONSE, EMPTY, { timeoutMs: 200 });
  await flush();

  // (b) exact wire text: Chromium's JSON.stringify of the object we posted.
  // len=0 | type=0a | 00 00 00 -> base64 "AAAAAAoAAAA".
  assert.equal(port.wire[0], '{"frame_b64":"AAAAAAoAAAA"}');

  port.reply(port.wire[0]);
  const result = await pending;
  assert.equal(result.type, MSG.USE_NATIVE_RESPONSE);
  assert.deepEqual(result.payload, EMPTY);
});

test('a reply parsed from wire text yields the frame (reverse direction)', async () => {
  // (d) Chromium parses the host's text before onMessage; the listener must
  // accept that object. The literal is the type-10 empty frame.
  const port = fakePort();
  const bridge = createBridge({ connectNative: () => port });

  const pending = bridge.request(MSG.GET_TOTP, EMPTY, { timeoutMs: 200 });
  await flush();

  port.reply('{"frame_b64":"AAAAAAoAAAA"}');
  const result = await pending;
  assert.equal(result.type, MSG.USE_NATIVE_RESPONSE);
  assert.deepEqual(result.payload, EMPTY);
});

test('a reply after the timeout is not handed to the next request', async () => {
  const port = fakePort();
  const bridge = createBridge({ connectNative: () => port });

  const first = bridge.request(MSG.LIST_CREDENTIALS, EMPTY, { timeoutMs: 200 });
  await flush();
  port.reply(replyFrame(MSG.AUTH_QUERY));
  assert.equal((await first).type, MSG.AUTH_QUERY);

  // A second reply with nobody waiting must be dropped, not queued.
  port.reply(replyFrame(MSG.RECOVER));
  await flush();

  const second = bridge.request(MSG.GET_PASSWORD, EMPTY, { timeoutMs: 200 });
  await flush();
  port.reply(replyFrame(MSG.GET_PASSWORD, fromHex('07')));
  const result = await second;

  // Got its own answer, not the earlier stray RECOVER.
  assert.equal(result.type, MSG.GET_PASSWORD);
  assert.deepEqual(Array.from(result.payload), [7]);
});

test('a silent host times out with the timeout code', async () => {
  const port = fakePort();
  const bridge = createBridge({ connectNative: () => port });
  await assert.rejects(
    bridge.request(MSG.GET_TOTP, EMPTY, { timeoutMs: 20 }),
    (err) => err instanceof BridgeError && err.code === 'timeout',
  );
});

test('a port that disconnects fails the pending request', async () => {
  const port = fakePort();
  const bridge = createBridge({ connectNative: () => port });

  const pending = bridge.request(MSG.GET_TOTP, EMPTY, { timeoutMs: 200 });
  await flush();
  port.emitDisconnect();

  await assert.rejects(
    pending,
    (err) => err instanceof BridgeError && err.code === 'disconnected',
  );
});

test('a missing host is reported, whether connectNative throws or returns nothing', async () => {
  const thrown = createBridge({
    connectNative() {
      throw new Error('no such host');
    },
  });
  await assert.rejects(
    thrown.request(MSG.GET_TOTP, EMPTY, { timeoutMs: 50 }),
    (err) => err instanceof BridgeError && err.code === 'host_missing',
  );

  const empty = createBridge({ connectNative: () => undefined });
  await assert.rejects(
    empty.request(MSG.GET_TOTP, EMPTY, { timeoutMs: 50 }),
    (err) => err instanceof BridgeError && err.code === 'host_missing',
  );
});

test('a malformed reply is a bad_response, never an empty object', async () => {
  const bad = [
    {}, // no key
    { frame_b64: '!!!' }, // bad base64
    { frame_b64: 'AAAAAAAAAAA', x: 1 }, // extra key
    { frame_b64: 123 }, // non-string value
    [], // array
    null, // not an object
    replyValue(11), // well-formed envelope, unknown message type
  ];
  for (const value of bad) {
    const port = fakePort();
    const bridge = createBridge({ connectNative: () => port });
    const pending = bridge.request(MSG.GET_TOTP, EMPTY, { timeoutMs: 200 });
    await flush();
    port.emitMessage(value);
    await assert.rejects(
      pending,
      (err) => err instanceof BridgeError && err.code === 'bad_response',
      `reply should be rejected: ${JSON.stringify(value)}`,
    );
  }
});

test('a string reply is a bad_response: Chromium delivers a parsed object', async () => {
  // Regression anchor: the old implementation required text, so a real
  // Chromium reply (an object) always failed. A string now means the peer
  // put JSON inside JSON, which the host cannot read.
  const port = fakePort();
  const bridge = createBridge({ connectNative: () => port });
  const pending = bridge.request(MSG.GET_TOTP, EMPTY, { timeoutMs: 200 });
  await flush();
  port.emitMessage(replyFrame(MSG.USE_NATIVE_RESPONSE));
  await assert.rejects(
    pending,
    (err) => err instanceof BridgeError && err.code === 'bad_response',
  );
});

// ---- nonce ----------------------------------------------------------------

test('newNonce is 16 random bytes as 32 hex characters', () => {
  const a = newNonce();
  const b = newNonce();
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.match(b, /^[0-9a-f]{32}$/);
  assert.notEqual(a, b);
});

// ---- service worker smoke -------------------------------------------------

test('the service worker module loads and registers its listener', async () => {
  globalThis.chrome = { runtime: { onMessage: { addListener() {} } } };
  const mod = await import('../src/background/service_worker.js');
  assert.ok(mod);
  delete globalThis.chrome;
});

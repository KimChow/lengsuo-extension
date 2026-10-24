// The service worker owns the trust boundary: a content script asks it to
// talk to the host, and it must first decide whether the sender's origin may
// have a credential at all.
//
// Each test imports a fresh copy of the module (via a query suffix) so the
// policy cache from one test cannot decide another test.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  MSG,
  BridgeError,
  encodeFrame,
  encodeEnvelope,
  frameOfEnvelope,
  decodeFrame,
} from '../src/background/native_bridge.js';

let counter = 0;

function chromeStub() {
  const listeners = [];
  return {
    runtime: {
      onMessage: {
        addListener(fn) {
          listeners.push(fn);
        },
      },
      connectNative() {
        throw new Error('connectNative must be stubbed by the test');
      },
    },
    _listeners: listeners,
  };
}

async function freshWorker() {
  globalThis.chrome = chromeStub();
  counter += 1;
  return import(`../src/background/service_worker.js?test=${counter}`);
}

function stubPolicy(policy) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, json: async () => policy });
  return () => {
    globalThis.fetch = original;
  };
}

async function waitFor(fn) {
  for (let i = 0; i < 100; i += 1) {
    if (fn()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('condition was never met');
}

// ---- policy gate -----------------------------------------------------------

test('a denied origin never reaches the host', async () => {
  const worker = await freshWorker();
  const restore = stubPolicy({ enable: [], disable: ['*'] });
  let connectCalls = 0;
  globalThis.chrome.runtime.connectNative = () => {
    connectCalls += 1;
    throw new Error('must not connect');
  };

  try {
    const result = await worker.handle(
      { kind: 'host_call', type: MSG.PASSKEY_CREATE, payload: { nonce: 1 } },
      'https://blocked.test/login',
    );

    // Anchor: replacing policyCheck with {allowed:true} turns this red.
    assert.deepEqual(result, { ok: false, reason: 'policy_denied' });
    assert.equal(connectCalls, 0, 'not a single byte may be sent when denied');
  } finally {
    restore();
  }
});

test('an unreachable policy service is denied, not allowed', async () => {
  const worker = await freshWorker();
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error('offline');
  };

  try {
    assert.deepEqual(await worker.policyCheck('https://allowed.test/'), {
      ok: true,
      allowed: false,
    });
  } finally {
    globalThis.fetch = original;
  }
});

test('an allowed origin reaches the host with a JSON-encoded payload', async () => {
  const worker = await freshWorker();
  const restore = stubPolicy({ enable: ['allowed.test'], disable: [] });

  const sent = [];
  let deliverMessage = null;
  const port = {
    postMessage(value) {
      sent.push(value);
    },
    onMessage: {
      addListener(fn) {
        deliverMessage = fn;
      },
    },
    onDisconnect: { addListener() {} },
    disconnect() {},
  };
  globalThis.chrome.runtime.connectNative = () => port;

  try {
    const pending = worker.handle(
      {
        kind: 'host_call',
        type: MSG.PASSKEY_GET,
        payload: { nonce: 7, origin: 'https://allowed.test' },
      },
      'https://allowed.test/login',
    );

    await waitFor(() => sent.length === 1);

    const frame = decodeFrame(frameOfEnvelope(sent[0]));
    assert.equal(frame.type, MSG.PASSKEY_GET);
    assert.deepEqual(JSON.parse(new TextDecoder().decode(frame.payload)), {
      nonce: 7,
      origin: 'https://allowed.test',
    });

    deliverMessage(JSON.parse(encodeEnvelope(encodeFrame(MSG.PASSKEY_GET, new Uint8Array(0)))));
    const result = await pending;
    assert.equal(result.ok, true);
    assert.equal(result.type, MSG.PASSKEY_GET);
  } finally {
    restore();
  }
});

// ---- hostCall --------------------------------------------------------------

test('hostCall sends UTF-8 JSON bytes and returns the typed reply', async () => {
  const worker = await freshWorker();
  const calls = [];
  const fake = {
    async request(type, bytes) {
      calls.push({ type, bytes });
      return { type: MSG.PASSKEY_GET, payload: new Uint8Array([1, 2]) };
    },
  };

  const result = await worker.hostCall(
    MSG.PASSKEY_CREATE,
    { nonce: 5, origin: 'https://shop.example.test' },
    fake,
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].type, MSG.PASSKEY_CREATE);
  assert.ok(calls[0].bytes instanceof Uint8Array);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0].bytes)), {
    nonce: 5,
    origin: 'https://shop.example.test',
  });
  assert.deepEqual(result, {
    ok: true,
    use_native: false,
    type: MSG.PASSKEY_GET,
    payload: new Uint8Array([1, 2]),
  });
});

test('hostCall refuses anything that is not a plain object', async () => {
  const worker = await freshWorker();
  let calls = 0;
  const fake = {
    async request() {
      calls += 1;
      return { type: MSG.PASSKEY_GET, payload: new Uint8Array(0) };
    },
  };

  for (const payload of [null, undefined, [1, 2], 'text', 42]) {
    const result = await worker.hostCall(MSG.PASSKEY_CREATE, payload, fake);
    assert.deepEqual(result, { ok: false, reason: 'bad_payload' });
  }
  assert.equal(calls, 0, 'a bad payload must never reach the bridge');
});

test('hostCall maps type 10 to the native fallback signal', async () => {
  const worker = await freshWorker();
  const fake = {
    async request() {
      return { type: MSG.USE_NATIVE_RESPONSE, payload: new Uint8Array(0) };
    },
  };

  assert.deepEqual(await worker.hostCall(MSG.PASSKEY_CREATE, { nonce: 1 }, fake), {
    ok: true,
    use_native: true,
  });
});

test('hostCall maps a bridge failure to its stable code', async () => {
  const worker = await freshWorker();
  const fake = {
    async request() {
      throw new BridgeError('host_missing', 'no registered host');
    },
  };

  assert.deepEqual(await worker.hostCall(MSG.PASSKEY_CREATE, { nonce: 1 }, fake), {
    ok: false,
    reason: 'host_missing',
    detail: 'no registered host',
  });
});

// ---- handle dispatch -------------------------------------------------------

test('handle rejects an unknown kind without touching the host', async () => {
  const worker = await freshWorker();
  assert.deepEqual(await worker.handle({ kind: 'nope' }, 'https://allowed.test/'), {
    ok: false,
    reason: 'unknown_kind',
  });
});

test('handle still answers policy_check for the old caller', async () => {
  const worker = await freshWorker();
  const restore = stubPolicy({ enable: ['allowed.test'], disable: [] });
  try {
    assert.deepEqual(await worker.handle({ kind: 'policy_check', url: 'https://allowed.test/' }), {
      ok: true,
      allowed: true,
    });
  } finally {
    restore();
  }
});

// The bridge to the local host over Chrome Native Messaging.
//
// Three layers, each with its own responsibility:
//   1. the transport frame  (length | type | reserved | payload) -- this file
//   2. the JSON envelope    ({"frame_b64":"..."}) -- this file
//   3. Chrome's own native pipe framing (4-byte native-order length + JSON
//      text) -- Chromium does this for us; we never touch it.
//
// Layers 1 and 2 are frozen in the cross-repo contract
// (lengsuo-browser/docs/credential-wire-contract.md §5.2 / §5.2.1). The Rust
// host side encodes the same bytes, so a wrong byte here is a broken channel.
//
// Everything except the thin `createBridge` IO layer is a pure function, so
// the wire format is testable under plain Node.
//
// The module top level must not touch `chrome.*`: tests import it in Node.

export const HOST_NAME = 'lengsuo.credential';

// Message types, matching the frozen protocol table (§5.3).
export const MSG = Object.freeze({
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
});

/** Largest payload the frame layer will carry. */
export const MAX_PAYLOAD_BYTES = 1024 * 1024;

const HEADER_BYTES = 8;
const MAX_TYPE = MSG.USE_NATIVE_RESPONSE;
const DEFAULT_TIMEOUT_MS = 5000;
const EMPTY = new Uint8Array(0);

/**
 * A channel failure. `code` is stable and belongs to the caller-visible
 * vocabulary: host_missing / disconnected / timeout / bad_response / bad_frame.
 */
export class BridgeError extends Error {
  constructor(code, detail = null) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'BridgeError';
    this.code = code;
    this.detail = detail;
  }
}

function badFrame(detail) {
  return new BridgeError('bad_frame', detail);
}

// ---- layer 1: transport frame ---------------------------------------------

/**
 * Encode one frame: len(u32 BE) | type(u8) | 000000 | payload.
 *
 * The length counts the payload only, never the eight header bytes.
 */
export function encodeFrame(type, payloadBytes) {
  if (!(payloadBytes instanceof Uint8Array)) {
    throw badFrame('payload must be a Uint8Array');
  }
  if (!Number.isInteger(type) || type < 0 || type > 0xff) {
    throw badFrame('type must be a byte');
  }
  if (payloadBytes.length > MAX_PAYLOAD_BYTES) {
    throw badFrame(`payload is ${payloadBytes.length} bytes, over the ${MAX_PAYLOAD_BYTES} limit`);
  }

  const len = payloadBytes.length;
  const out = new Uint8Array(HEADER_BYTES + len);
  out[0] = (len >>> 24) & 0xff;
  out[1] = (len >>> 16) & 0xff;
  out[2] = (len >>> 8) & 0xff;
  out[3] = len & 0xff;
  out[4] = type;
  // out[5..8] are reserved and stay zero.
  out.set(payloadBytes, HEADER_BYTES);
  return out;
}

/**
 * Decode one frame. Anything that does not match the layout exactly is a
 * failure; there is no "best effort" parse of a credential frame.
 */
export function decodeFrame(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw badFrame('frame must be a Uint8Array');
  }
  if (bytes.length < HEADER_BYTES) {
    throw badFrame('frame is shorter than its header');
  }

  const len = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  if (bytes[5] !== 0 || bytes[6] !== 0 || bytes[7] !== 0) {
    throw badFrame('reserved bytes must be zero');
  }
  if (len > MAX_PAYLOAD_BYTES) {
    throw badFrame(`declared length ${len} is over the ${MAX_PAYLOAD_BYTES} limit`);
  }
  if (bytes.length !== HEADER_BYTES + len) {
    throw badFrame(`declared length ${len} does not match ${bytes.length - HEADER_BYTES} payload bytes`);
  }

  const type = bytes[4];
  if (type > MAX_TYPE) {
    throw badFrame(`unknown message type ${type}`);
  }

  return { type, payload: bytes.slice(HEADER_BYTES) };
}

// ---- layer 2: base64 and the JSON envelope --------------------------------

function binaryStringOf(bytes) {
  // Chunked: spreading a 1 MiB array into String.fromCharCode would overflow
  // the argument limit.
  const chunk = 0x8000;
  let text = '';
  for (let i = 0; i < bytes.length; i += chunk) {
    text += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return text;
}

/** Base64 without '=' padding, matching the Rust side. */
export function base64Encode(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw badFrame('base64 input must be a Uint8Array');
  }
  return btoa(binaryStringOf(bytes)).replace(/=+$/, '');
}

/**
 * Base64 decode that tolerates missing padding but nothing else.
 *
 * Padding is accepted only at the end, in the correct amount; URL-safe
 * characters, whitespace, empty input, and impossible lengths are refused.
 */
export function base64Decode(text) {
  if (typeof text !== 'string' || text.length === 0) {
    throw badFrame('base64 input must be a non-empty string');
  }

  let padding = 0;
  if (text.endsWith('==')) padding = 2;
  else if (text.endsWith('=')) padding = 1;
  const body = text.slice(0, text.length - padding);

  if (body.includes('=')) {
    throw badFrame('base64 padding must be at the end');
  }
  if (!/^[A-Za-z0-9+/]+$/.test(body)) {
    throw badFrame('base64 contains a non-base64 character');
  }
  if (body.length % 4 === 1) {
    throw badFrame('base64 length is impossible');
  }
  if (padding > 0 && (body.length + padding) % 4 !== 0) {
    throw badFrame('base64 padding is inconsistent with its length');
  }

  const padded = body + '='.repeat((4 - (body.length % 4)) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw badFrame('base64 could not be decoded');
  }

  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * The envelope as a JS value: exactly what `port.postMessage` must receive.
 *
 * Chromium stringifies this object itself before writing the JSON line to the
 * host (`messaging_util.cc`), so the host sees `{"frame_b64":"..."}`. Handing
 * Chromium a *string* would instead put quotes and escapes around it.
 */
export function envelopeOf(frameBytes) {
  if (!(frameBytes instanceof Uint8Array)) {
    throw badFrame('envelope body must be a frame');
  }
  return { frame_b64: base64Encode(frameBytes) };
}

/**
 * The same envelope as wire text: no spaces, one key (§5.2.1).
 *
 * Only for pinning the bytes the host will read; production never calls it.
 * `JSON.stringify(envelopeOf(f))` must equal `encodeEnvelope(f)`.
 */
export function encodeEnvelope(frameBytes) {
  if (!(frameBytes instanceof Uint8Array)) {
    throw badFrame('envelope body must be a frame');
  }
  return `{"frame_b64":"${base64Encode(frameBytes)}"}`;
}

/**
 * Unwrap the envelope Chromium hands to `onMessage`.
 *
 * Chromium has already parsed the wire JSON into an object before the listener
 * runs (`gin_port.cc` MessageToV8), so this validates an object, not text. A
 * string here means the peer put JSON *inside* JSON: the host would look for
 * `frame_b64` and find none. Legality of the frame is judged by decodeFrame.
 */
export function frameOfEnvelope(value) {
  if (typeof value === 'string') {
    throw badFrame(
      'envelope arrived as text; Chromium already parsed it, so a string means the peer implementation is wrong',
    );
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw badFrame('envelope must be an object');
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw badFrame('envelope must be a plain object');
  }

  const keys = Object.keys(value);
  if (keys.length !== 1 || keys[0] !== 'frame_b64') {
    throw badFrame('envelope must have exactly one frame_b64 key');
  }
  if (typeof value.frame_b64 !== 'string') {
    throw badFrame('frame_b64 must be a string');
  }

  return base64Decode(value.frame_b64);
}

// ---- the channel ----------------------------------------------------------

/**
 * Build a request/response channel over one injected native port.
 *
 * `connectNative` is injected so tests can supply a fake and so this module
 * never mentions `chrome` at import time. Requests are serialised: one reply
 * is matched to one request, and a stray reply is dropped rather than allowed
 * to answer the next request.
 */
export function createBridge({ connectNative, now = () => Date.now() } = {}) {
  if (typeof connectNative !== 'function') {
    throw new TypeError('connectNative must be a function');
  }

  let port = null;
  let current = null; // { timer, resolve, reject } for the in-flight request
  let closed = false;
  let chain = Promise.resolve(); // serialises requests

  function onMessage(message) {
    const slot = current;
    if (!slot) return; // nobody is waiting: drop it

    current = null;
    clearTimeout(slot.timer);
    try {
      // Chromium delivers an already-parsed object, never wire text.
      slot.resolve(decodeFrame(frameOfEnvelope(message)));
    } catch (err) {
      slot.reject(new BridgeError('bad_response', String(err && err.message ? err.message : err)));
    }
  }

  function onDisconnect() {
    port = null;
    const slot = current;
    current = null;
    if (!slot) return;
    clearTimeout(slot.timer);
    slot.reject(new BridgeError('disconnected'));
  }

  function openPort() {
    if (port) return port;

    let candidate;
    try {
      candidate = connectNative(HOST_NAME);
    } catch (err) {
      throw new BridgeError('host_missing', String(err));
    }
    if (
      !candidate ||
      typeof candidate.postMessage !== 'function' ||
      !candidate.onMessage ||
      typeof candidate.onMessage.addListener !== 'function' ||
      !candidate.onDisconnect ||
      typeof candidate.onDisconnect.addListener !== 'function'
    ) {
      throw new BridgeError('host_missing', 'connectNative returned no usable port');
    }

    candidate.onMessage.addListener(onMessage);
    candidate.onDisconnect.addListener(onDisconnect);
    port = candidate;
    return candidate;
  }

  function doRequest(type, payloadBytes, timeoutMs) {
    return new Promise((resolve, reject) => {
      if (closed) {
        reject(new BridgeError('disconnected', 'bridge is closed'));
        return;
      }

      let envelope;
      try {
        // An object, not text: Chromium stringifies whatever value it gets.
        envelope = envelopeOf(encodeFrame(type, payloadBytes));
      } catch (err) {
        reject(err);
        return;
      }

      let activePort;
      try {
        activePort = openPort();
      } catch (err) {
        reject(err);
        return;
      }

      const startedAt = now();
      const slot = { timer: null, resolve, reject };
      slot.timer = setTimeout(() => {
        if (current !== slot) return;
        current = null;
        // A late reply must not be mistaken for the next request's answer,
        // so the connection is torn down rather than left half-used.
        try {
          activePort.disconnect();
        } catch {
          // already disconnected
        }
        if (port === activePort) port = null;
        reject(new BridgeError('timeout', `no reply within ${timeoutMs}ms (waited ${now() - startedAt}ms)`));
      }, timeoutMs);
      current = slot;

      try {
        activePort.postMessage(envelope);
      } catch (err) {
        if (current === slot) current = null;
        if (port === activePort) port = null;
        clearTimeout(slot.timer);
        reject(new BridgeError('disconnected', String(err)));
      }
    });
  }

  function request(type, payloadBytes, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    const wait = typeof timeoutMs === 'number' && timeoutMs >= 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
    const payload = payloadBytes ?? EMPTY;
    const run = () => doRequest(type, payload, wait);
    const result = chain.then(run, run);
    chain = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  function close() {
    closed = true;
    const slot = current;
    current = null;
    const activePort = port;
    port = null;

    if (slot) {
      clearTimeout(slot.timer);
      slot.reject(new BridgeError('disconnected', 'bridge closed'));
    }
    if (activePort) {
      try {
        activePort.disconnect();
      } catch {
        // already disconnected
      }
    }
  }

  return { request, close };
}

/** A one-shot nonce, so a replayed request is recognisable (§5.1). */
export function newNonce() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Ed25519 signature verification for fill script packages.
//
// Pure function. Verifies an Ed25519 signature over the JCS-canonical bytes
// of a package (with the `signature` object stripped). The public key used for
// verification is the one declared inside the package itself
// (signature.public_key_b64url); the built-in key equality check lives in
// schema.validatePackage and the content script's initial screen, so
// verify.js stays key-agnostic and testable with an embedded fixed test key
// pair.
//
// ⚠ 每条改动必须同步更新 content/fill_script_content.js 的内联实现。

import { createPublicKey, verify } from 'node:crypto';
import { normalize } from './normalize.js';

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // Ed25519 subjectPublicKeyInfo

// Built-in public key (b64url, no padding), pinned byte-for-byte in
// local-docs/fill-script-signing-dev-key.md. Used by schema/content-script to
// reject packages signed by unknown signers. verify.js itself verifies against
// the key declared in each package, so this constant is only re-exported for
// callers that want the built-in equality check.
export const BUILTIN_PUBLIC_KEY_B64URL =
  'QRSkzRfE_MdzvmNmzKy_sWp6W0NTouBch_f5R_OFu8A';

function b64urlDecode(text) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('bad signature: signature_b64url must be a non-empty string');
  }
  let s = text.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 === 1) s = 'A' + s; // impossible length fix-up
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function importRawPublicKey(raw32) {
  const der = Buffer.concat([SPKI_PREFIX, Buffer.from(raw32)]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function stripSignature(obj) {
  const { signature: _ignored, ...unsigned } = obj;
  return unsigned;
}

export function verifyPackage(input) {
  let obj;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    obj = JSON.parse(Buffer.from(input).toString('utf8'));
  } else if (typeof input === 'string') {
    obj = JSON.parse(input);
  } else if (input && typeof input === 'object' && !Array.isArray(input)) {
    obj = input;
  } else {
    return false;
  }

  const sig = obj && obj.signature;
  if (!sig || sig.alg !== 'Ed25519') return false;
  if (typeof sig.signature_b64url !== 'string') return false;
  if (typeof sig.public_key_b64url !== 'string') return false;

  let signature;
  try {
    signature = b64urlDecode(sig.signature_b64url);
  } catch {
    return false;
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;

  let raw32;
  try {
    raw32 = b64urlDecode(sig.public_key_b64url);
  } catch {
    return false;
  }
  if (raw32.length !== 32) return false;

  let publicKey;
  try {
    publicKey = importRawPublicKey(raw32);
  } catch {
    return false;
  }

  const data = Buffer.from(normalize(stripSignature(obj)), 'utf8');
  return verify(null, data, publicKey, signature);
}

export function isBuiltinSigner(publicKeyB64url) {
  return publicKeyB64url === BUILTIN_PUBLIC_KEY_B64URL;
}

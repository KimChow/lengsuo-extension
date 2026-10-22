// The extension id must not drift.
//
// Chromium derives an unpacked extension's id from the manifest "key" field.
// Without that field it falls back to deriving the id from the install path,
// which changes whenever the kernel package layout changes.
//
// The algorithm, from the browser source:
//   id = hex(SHA256(publicKeyBytes)[0..16]) with each hex digit mapped to
//        'a' + value, giving 32 characters from the alphabet a-p.
//
// This test pins the value so a key change cannot pass unnoticed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXT = dirname(dirname(fileURLToPath(import.meta.url)));

/** The id the browser will compute for the public key. */
function computeExtensionId(spkiDer) {
  const hash = createHash('sha256').update(spkiDer).digest();
  const hex = hash.subarray(0, 16).toString('hex');
  let id = '';
  for (const ch of hex) id += String.fromCharCode('a'.charCodeAt(0) + parseInt(ch, 16));
  return id;
}

/** The public key bytes, decoded the way the browser decodes the manifest field. */
function publicKeyBytesFromManifest(manifest) {
  const raw = manifest.key;
  assert.equal(typeof raw, 'string', 'manifest must carry a "key" field');
  assert.ok(raw.length > 0, 'the "key" field must not be empty');

  let body = raw;
  if (raw.startsWith('-----BEGIN')) {
    body = body.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '');
  }
  body = body.replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}

test('the manifest carries the key field, so the id cannot drift with the path', async () => {
  const manifest = JSON.parse(
    await readFile(join(EXT, 'manifest.json'), 'utf8'),
  );
  assert.ok(manifest.key, 'manifest.json must have a "key" field');
});

test('the manifest key decodes to the same bytes as the tracked public key', async () => {
  const manifest = JSON.parse(
    await readFile(join(EXT, 'manifest.json'), 'utf8'),
  );
  const fromManifest = publicKeyBytesFromManifest(manifest);

  const der = execFileSync(
    'openssl',
    ['rsa', '-in', join(EXT, 'keys', 'extension_private_key.pem'), '-pubout', '-outform', 'DER'],
    { maxBuffer: 1 << 20 },
  );

  // The tracked public key and the manifest key must be the same key.
  const tracked = execFileSync(
    'openssl',
    ['rsa', '-pubin', '-in', join(EXT, 'keys', 'extension_public_key.pem'), '-outform', 'DER'],
    { maxBuffer: 1 << 20 },
  );
  assert.deepEqual(fromManifest, Buffer.from(tracked));
  assert.ok(der.length > 0);
});

test('the extension id is the pinned value', async () => {
  const manifest = JSON.parse(
    await readFile(join(EXT, 'manifest.json'), 'utf8'),
  );
  const id = computeExtensionId(publicKeyBytesFromManifest(manifest));

  // 32 characters, alphabet a-p: this is what the browser requires.
  assert.match(id, /^[a-p]{32}$/);

  // Pinned. Changing the public key changes the id, which invalidates every
  // registered Native Messaging host, so it has to be a deliberate edit.
  assert.equal(id, 'ejlmmjamfpkoopjachjhcbdjlddknhok');
});

// The repository holds more than one extension. These tests keep the layout
// honest: a new extension must be a directory with the right shape, and the
// build must find it without any change to the build script.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access, stat, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { listExtensions, buildExtension, digestDirectory } from '../build/build.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const EXTENSIONS_DIR = join(ROOT, 'extensions');

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

test('at least one extension is present', async () => {
  const names = await listExtensions();
  assert.ok(names.length > 0, 'extensions/ must not be empty');
});

test('every extension has the required shape', async () => {
  const names = await listExtensions();
  for (const name of names) {
    const base = join(EXTENSIONS_DIR, name);
    assert.ok(await exists(join(base, 'manifest.json')), `${name}: manifest.json missing`);
    assert.ok(await exists(join(base, 'src')), `${name}: src/ missing`);
    assert.ok(
      await exists(join(base, 'keys', 'extension_public_key.pem')),
      `${name}: the fixed public key must be present`,
    );
  }
});

test('the manifest declares the native messaging permission', async () => {
  const names = await listExtensions();
  for (const name of names) {
    const raw = await readFile(join(EXTENSIONS_DIR, name, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(raw);
    assert.equal(manifest.manifest_version, 3, `${name}: must be MV3`);
    assert.ok(
      (manifest.permissions || []).includes('nativeMessaging'),
      `${name}: nativeMessaging permission missing`,
    );
  }
});

// The manifest references paths relative to the package root, which the
// source tree holds under src/. A reference with no file behind it loads
// nothing in the browser, so every local reference must stat as a real file.
test('the manifest only references files that exist in the extension source', async () => {
  const names = await listExtensions();
  for (const name of names) {
    const raw = await readFile(join(EXTENSIONS_DIR, name, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(raw);
    const refs = [];

    if (manifest.background?.service_worker) {
      refs.push(manifest.background.service_worker);
    }
    for (const script of manifest.content_scripts || []) {
      refs.push(...(script.js || []));
    }
    for (const resource of manifest.web_accessible_resources || []) {
      for (const item of resource.resources || []) {
        // Globs and external URLs (scheme:) are not single files to stat.
        if (!item.includes('*') && !/^[a-z][a-z0-9+.-]*:/.test(item)) {
          refs.push(item);
        }
      }
    }

    for (const ref of refs) {
      const info = await stat(join(EXTENSIONS_DIR, name, 'src', ref)).catch(() => null);
      assert.ok(
        info?.isFile(),
        `${name}: manifest references src/${ref}, which is missing or not a file`,
      );
    }
  }
});

test('an extension builds into a package with the expected shape', async () => {
  const names = await listExtensions();
  const first = names[0];

  // Build into a scratch directory: the test must not remove anything from
  // the working tree, and a scratch root keeps it out of the way.
  const scratch = await mkdtemp(join(tmpdir(), 'lengsuo-ext-build-'));
  const out = await buildExtension(first, scratch);

  const { digest, files } = await digestDirectory(out);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.ok(files.includes('manifest.json'));
  assert.ok(files.length > 1, 'package must hold the manifest plus at least one file');
});

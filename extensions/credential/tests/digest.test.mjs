// The directory digest is cross-repo: the Rust side in the kernel package
// crate must produce the same value. The vectors here are the contract.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { digestDirectory } from '../../../build/build.mjs';

async function scratch() {
  return mkdtemp(join(tmpdir(), 'lengsuo-ext-'));
}

test('an empty directory digests to the sha256 of nothing', async () => {
  const dir = await scratch();
  try {
    const { digest, files } = await digestDirectory(dir);
    assert.deepEqual(files, []);
    assert.equal(digest, createHash('sha256').digest('hex'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the digest does not depend on write order', async () => {
  const a = await scratch();
  const b = await scratch();
  try {
    await mkdir(join(a, 'sub'), { recursive: true });
    await writeFile(join(a, 'one.txt'), 'one');
    await writeFile(join(a, 'sub', 'two.txt'), 'two');

    await mkdir(join(b, 'sub'), { recursive: true });
    await writeFile(join(b, 'sub', 'two.txt'), 'two');
    await writeFile(join(b, 'one.txt'), 'one');

    const first = await digestDirectory(a);
    const second = await digestDirectory(b);
    assert.equal(first.digest, second.digest);
  } finally {
    await rm(a, { recursive: true, force: true });
    await rm(b, { recursive: true, force: true });
  }
});

test('changing a file changes the digest', async () => {
  const dir = await scratch();
  try {
    await writeFile(join(dir, 'a.txt'), 'a');
    const before = await digestDirectory(dir);
    await writeFile(join(dir, 'a.txt'), 'b');
    const after = await digestDirectory(dir);
    assert.notEqual(before.digest, after.digest);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('renaming a file changes the digest', async () => {
  const dir = await scratch();
  try {
    await writeFile(join(dir, 'a.txt'), 'a');
    const before = await digestDirectory(dir);
    await writeFile(join(dir, 'b.txt'), 'a');
    const after = await digestDirectory(dir);
    assert.notEqual(before.digest, after.digest);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// Build every extension in extensions/ into dist/<name>/ and print the
// deterministic digest of each.
//
// The digest algorithm is frozen in the cross-repo contract
// (lengsuo-browser/docs/credential-wire-contract.md §5.5). The Rust side
// implements the same algorithm; both sides must agree on the fixed vectors.
//
// This repository holds more than one extension, so the build walks
// extensions/ and treats each subdirectory as one extension. Adding an
// extension means adding a directory; no change to this file is needed.
//
// Usage:
//   node build/build.mjs            build all
//   node build/build.mjs --digest   build all and print digests as JSON
//   node build/build.mjs credential build one, by directory name
//
// No dependencies: node >= 18 for node:crypto and node:test.

import { createHash } from 'node:crypto';
import { readdir, readFile, mkdir, copyFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const EXTENSIONS_DIR = join(ROOT, 'extensions');
const DIST = join(ROOT, 'dist');

// Files copied verbatim from an extension root into its package root.
const ROOT_FILES = ['manifest.json'];

/**
 * List every regular file under `dir`, as POSIX-style relative paths.
 *
 * Symbolic links are skipped, matching the kernel package archive rules
 * (`ArchiveError::UnsupportedKind`).
 */
export async function listFiles(dir) {
  const out = [];

  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        out.push(relative(dir, full).split(sep).join('/'));
      }
      // Symlinks and other kinds are deliberately skipped.
    }
  }

  await walk(dir);
  // Byte-order sort by UTF-8 bytes (contract §5.5). NOT `a < b`: that compares
  // UTF-16 code units, which orders astral characters differently.
  out.sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
  return out;
}

/**
 * The frozen digest algorithm.
 *
 * For every file, in sorted relative-path order, feed into one hash:
 *   path bytes || 0x00 || raw 32-byte sha256 of the content || 0x00
 * The final digest is the sha256 of that stream.
 */
export async function digestDirectory(dir) {
  const files = await listFiles(dir);
  const outer = createHash('sha256');

  for (const rel of files) {
    const content = await readFile(join(dir, rel));
    const fileHash = createHash('sha256').update(content).digest();

    outer.update(Buffer.from(rel, 'utf8'));
    outer.update(Buffer.from([0x00]));
    outer.update(fileHash);
    outer.update(Buffer.from([0x00]));
  }

  return { digest: outer.digest('hex'), files };
}

// Hand-copied from the Rust-side vector file
// (lengsuo-browser-package/tests/vectors/extension-digest-v1.json,
// "astral_unicode"). Never replace it with this implementation's own output:
// that would make the check vacuous.
const ASTRAL_VECTOR_DIGEST =
  '25c14558538bb11a3c3ab86e236c64816d56662f9b58134e33540551e7c2b912';

/**
 * Prove that relative paths are sorted by UTF-8 byte order, as §5.5 requires.
 *
 * The fixture is byte-for-byte the Rust vector's "astral_unicode" case:
 * U+E000 ("x") and U+1F600 ("e"). UTF-16 code unit order puts the surrogate
 * pair (U+1F600) first; UTF-8 byte order puts U+E000 first. Only the latter
 * matches the frozen cross-repo digest.
 */
export async function digestOrderingSelfCheck() {
  const dir = await mkdtemp(join(tmpdir(), 'lengsuo-digest-order-'));
  try {
    await writeFile(join(dir, '\uE000.txt'), 'x');
    await writeFile(join(dir, '\u{1F600}.txt'), 'e');

    const { digest } = await digestDirectory(dir);
    if (digest !== ASTRAL_VECTOR_DIGEST) {
      throw new Error(
        `digest ordering self-check failed: expected ${ASTRAL_VECTOR_DIGEST}, got ${digest}\n` +
          'relative paths must be sorted by UTF-8 byte order (contract §5.5), ' +
          'not by UTF-16 code units',
      );
    }
    process.stderr.write('digest ordering self-check: ok\n');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** The extensions present in this repository, by directory name. */
export async function listExtensions() {
  const entries = await readdir(EXTENSIONS_DIR, { withFileTypes: true });
  return entries
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

/**
 * Make sure `dir` exists.
 *
 * The build overwrites files in place rather than clearing the directory
 * first. Deleting a tree is not reliable here: a recycle-bin style shim can
 * intercept the removal and time out. A stale file would survive a clear,
 * so the digest is what actually proves the contents.
 */
async function ensureDirectory(dir) {
  await mkdir(dir, { recursive: true });
}

async function copyTree(from, to) {
  const files = await listFiles(from);
  for (const rel of files) {
    const dest = join(to, rel);
    await mkdir(dirname(dest), { recursive: true });
    await copyFile(join(from, rel), dest);
  }
  return files;
}

/**
 * Build one extension into dist/<name>/.
 *
 * Files are written over the previous contents. The directory is not
 * cleared: removing a tree can be intercepted by tooling that moves it to a
 * trash bin, which is slow and can fail. The digest is what proves what the
 * package contains.
 */
export async function buildExtension(name, outRoot = DIST) {
  const src = join(EXTENSIONS_DIR, name);
  const out = join(outRoot, name);

  await ensureDirectory(out);

  for (const file of ROOT_FILES) {
    await copyFile(join(src, file), join(out, file));
  }
  await copyTree(join(src, 'src'), join(out, 'src'));

  return out;
}

async function main() {
  await digestOrderingSelfCheck();

  const args = process.argv.slice(2);
  const wantDigest = args.includes('--digest');
  const only = args.filter((a) => !a.startsWith('--'));

  const all = await listExtensions();
  if (all.length === 0) {
    throw new Error('no extensions found under extensions/');
  }
  const names = only.length > 0 ? only : all;

  for (const name of names) {
    if (!all.includes(name)) {
      throw new Error(`unknown extension: ${name} (have: ${all.join(', ')})`);
    }
  }

  await ensureDirectory(DIST);

  const results = [];
  for (const name of names) {
    await buildExtension(name);
    const out = join(DIST, name);

    if (wantDigest) {
      const { digest, files } = await digestDirectory(out);
      results.push({ name, digest, file_count: files.length, files });
    } else {
      results.push({ name, digest: null, file_count: (await listFiles(out)).length, files: [] });
    }
  }

  if (wantDigest) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else {
    for (const r of results) {
      process.stdout.write(`built dist/${r.name}/ (${r.file_count} files)\n`);
    }
  }
}

// Only build when this file is the entry point. A test that imports the
// helpers must not trigger a build as a side effect.
const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];

if (invokedDirectly) {
  main().catch((err) => {
    process.stderr.write(String(err && err.stack ? err.stack : err) + '\n');
    process.exit(1);
  });
}

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
import { readdir, readFile, mkdir, copyFile } from 'node:fs/promises';
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
  // Byte-order sort: locale-independent, so every machine agrees.
  out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
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

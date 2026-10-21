# lengsuo-extension

Lengsuo browser extensions.

This repository holds **one extension per directory** under `extensions/`.
Adding an extension means adding a directory; the build script needs no
change.

```
extensions/
  credential/     the credential extension (Passkey, password, TOTP)
```

> **文档不入库**：`docs/` 全部只保留在本地开发工作区（用于开发进展与验收记录），不随仓库分发，
> 也不保留在 git 历史中。需要查阅请找开发方索取。

## What lives where

| Extension | Holds |
|---|---|
| `credential` | the page-side half of the credential system: the main-world script that intercepts `navigator.credentials`, the content-script bridges, the fill entry points, and the allow-list policy |

The private key handling, the credential vault and the Native Messaging host
live in the client repository. Extensions here hold no secrets and never talk
to the server directly.

## Build

```bash
node build/build.mjs            # builds every extension into dist/<name>/
node build/build.mjs --digest   # also prints the deterministic digest
node build/build.mjs credential # builds one extension only
```

The digest is a cross-repo contract: the kernel package crate computes the
same value over the same directory. The algorithm is frozen in
`lengsuo-browser/docs/credential-wire-contract.md` §5.5.

## Test

```bash
node --test "tests/*.test.mjs" "extensions/*/tests/*.test.mjs"
```

`tests/` holds the repository-level tests (layout, shared rules); each
extension holds its own under `extensions/<name>/tests/`.

## Fixed values

| What | Value |
|---|---|
| Native Messaging host name | `lengsuo.credential` |
| Extension id (credential) | `SbzJDF-u75AnlyE5` |
| Extension directory name | `lengsuo-credential` |

An extension id is derived from that extension's public key. Changing the key
changes the id, which invalidates every registered Native Messaging host, so
the public key is tracked and the private key is not.

Each extension has its own key pair, and therefore its own id.

## Licence

MIT OR Apache-2.0. See `LICENSE` and `LICENSES/`.

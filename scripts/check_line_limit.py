#!/usr/bin/env python3
"""Line count gate.

The project limit is 700 lines hard, 400 lines a soft target. The soft target
is reported as a warning so a file that is deliberately long can explain
itself; the hard limit is a failure.

Usage: python3 scripts/check_line_limit.py [root]
"""

import sys
from pathlib import Path

HARD_LIMIT = 700
SOFT_TARGET = 400

SKIP_DIRS = {".git", "node_modules", "dist", ".github"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pem", ".key", ".woff", ".woff2"}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    failures = 0
    warnings = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            lines = len(path.read_text(encoding="utf-8").splitlines())
        except (UnicodeDecodeError, OSError):
            continue

        rel = path.relative_to(root)
        if lines > HARD_LIMIT:
            print(f"FAIL {rel}: {lines} > {HARD_LIMIT}")
            failures += 1
        elif lines > SOFT_TARGET:
            print(f"WARN {rel}: {lines} > {SOFT_TARGET}; explain or split")
            warnings += 1

    print(f"Checked {root.name}; hard-limit failures: {failures}; soft-target warnings: {warnings}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

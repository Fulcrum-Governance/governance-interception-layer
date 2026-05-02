#!/usr/bin/env python3
"""Bootstrap graphify-out/manifest.json so the next `graphify update` is incremental.

Why this exists
---------------
`graphify update <repo>` re-extracts the AST and rebuilds the graph but does NOT
write `graphify-out/manifest.json`. The manifest is what makes subsequent runs
incremental — it stores the mtime of every file so `detect_incremental` can skip
unchanged files. Without a manifest the next "incremental" run re-extracts
everything, which is a regression in cost and wall time.

This script calls `graphify.detect.detect()` once to inventory the repo, then
calls `graphify.detect.save_manifest()` to record current mtimes. After the first
run `graphify update .` correctly identifies the baseline and operates
incrementally.

Usage
-----
    python3 scripts/bootstrap_graphify_manifest.py

Run from the repo root. Writes to `graphify-out/manifest.json`. `graphify-out/`
is a per-clone artifact (excluded via `.git/info/exclude`), so this script is
idempotent: re-run it any time the local manifest goes stale, or after a
`graphify update` that did not write one.
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    try:
        from graphify.detect import detect, save_manifest
    except ImportError:
        print(
            "error: graphify is not installed. "
            "Install with `uv tool install graphifyy` or `pip install graphifyy`.",
            file=sys.stderr,
        )
        return 1

    root = Path.cwd()
    out = root / "graphify-out"
    if not out.exists():
        out.mkdir(parents=True)

    detected = detect(root)
    save_manifest(detected["files"])

    manifest_path = out / "manifest.json"
    print(
        f"wrote {manifest_path.relative_to(root)} "
        f"({detected['total_files']} files indexed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

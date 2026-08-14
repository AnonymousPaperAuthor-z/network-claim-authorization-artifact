#!/usr/bin/env python3
"""Build the repository-level SHA-256 manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "RELEASE_MANIFEST.json"
IGNORED = {".git", "outputs", "__pycache__", ".DS_Store"}


def main() -> int:
    rows = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path == OUTPUT:
            continue
        relative = path.relative_to(ROOT)
        if any(part in IGNORED for part in relative.parts):
            continue
        rows.append(
            {
                "path": str(relative),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    payload = {
        "schema_version": "vericlaim-release-manifest-v1",
        "submission_scope": "anonymous conference artifact",
        "files": rows,
    }
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"files": len(rows), "output": OUTPUT.name}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

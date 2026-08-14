#!/usr/bin/env python3
"""Enforce the minimal anonymous-submission file and content boundary."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".git", "outputs", "__pycache__", ".pytest_cache", ".DS_Store"}
ALLOWED_ROOT_FILES = {
    ".gitignore",
    "Dockerfile",
    "LICENSE",
    "Makefile",
    "README.md",
    "RELEASE_MANIFEST.json",
    "pyproject.toml",
    "requirements.txt",
}
ALLOWED_ROOT_DIRS = {
    "benchmark",
    "config",
    "data",
    "probeagent",
    "scripts",
    "tests",
    "training",
}
ALLOWED_MARKDOWN = {
    Path("README.md"),
    Path("benchmark/vericlaim_sec/README.md"),
    Path("training/vericlaim_sec/README.md"),
}
FORBIDDEN_SUFFIXES = {
    ".csv",
    ".doc",
    ".docx",
    ".log",
    ".pdf",
    ".tex",
    ".xls",
    ".xlsm",
    ".xlsx",
}
FORBIDDEN_PATH_TERMS = {
    "archive",
    "discussion",
    "draft",
    "intermediate",
    "journal",
    "manual_review",
    "notes",
    "private",
    "report",
    "scratch",
    "status",
    "workbook",
}
DATED_NAME = re.compile(r"(?:19|20)\d{6}")
REVISION_NAME = re.compile(r"(?:^|[_-])r\d+(?:[_-]|$)", re.IGNORECASE)
POST_SUBMISSION_TERMS = (
    "second independent holdout",
    "hierarchical source-dependency",
    "record-level risk certificate",
    "journal extension",
)


def main() -> int:
    errors: list[str] = []
    files = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if any(part in IGNORED for part in relative.parts):
            continue
        files.append(relative)
        if relative.parts[0] not in ALLOWED_ROOT_DIRS and relative.name not in ALLOWED_ROOT_FILES:
            errors.append(f"unexpected root asset: {relative}")
        if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
            errors.append(f"intermediate or manuscript asset: {relative}")
        if path.suffix.casefold() == ".md" and relative not in ALLOWED_MARKDOWN:
            errors.append(f"unexpected Markdown file: {relative}")
        lowered = str(relative).casefold()
        if any(term in lowered for term in FORBIDDEN_PATH_TERMS):
            errors.append(f"non-release path term: {relative}")
        if DATED_NAME.search(relative.name) or REVISION_NAME.search(relative.name):
            errors.append(f"dated or revision-specific release filename: {relative}")
        if path.suffix.casefold() in {".json", ".md", ".py", ".toml", ".txt"}:
            text = path.read_text(encoding="utf-8").casefold()
            if relative != Path("scripts/verify_submission_scope.py"):
                for term in POST_SUBMISSION_TERMS:
                    if term in text:
                        errors.append(f"out-of-scope extension term {term!r}: {relative}")

    required = {
        Path("README.md"),
        Path("benchmark/vericlaim_sec/README.md"),
        Path("benchmark/vericlaim_sec/release_manifest.json"),
        Path("training/vericlaim_sec/README.md"),
        Path("training/vericlaim_sec/release_manifest.json"),
        Path("scripts/run_all.py"),
        Path("scripts/run_eev.py"),
        Path("scripts/run_pase.py"),
        Path("scripts/verify_release.py"),
    }
    for relative in sorted(required):
        if relative not in files:
            errors.append(f"missing required release asset: {relative}")

    report = {
        "status": "PASS" if not errors else "FAIL",
        "files_checked": len(files),
        "errors": errors,
    }
    output = ROOT / "outputs/submission_scope_gate.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

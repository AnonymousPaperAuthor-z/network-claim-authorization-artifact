#!/usr/bin/env python3
"""Fail closed when release files contain identity, secret, or size hazards."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".cfg",
    ".gitignore",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yml",
    ".yaml",
}
IGNORED_PARTS = {
    ".git",
    ".DS_Store",
    "__pycache__",
    ".pytest_cache",
    "outputs",
}
FORBIDDEN_PATTERNS = {
    "local_user_path": re.compile(r"/Users/|/home/|/data/"),
    "private_ipv4": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
    ),
    "credential_assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*"
        r"[\"']?[A-Za-z0-9_\-]{12,}"
    ),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "known_provider_credential": re.compile(
        r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|"
        r"AIza[0-9A-Za-z_-]{20,}|(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}|"
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
        r"[A-Za-z0-9_-]{10,})"
    ),
    "bearer_credential": re.compile(
        r"(?i)\bBearer\s+(?!<REDACTED(?:_TOKEN)?>)"
        r"[A-Za-z0-9][A-Za-z0-9._~+/=-]{16,}"
    ),
    "personal_email": re.compile(
        r"(?i)\b[A-Z0-9._%+\-]+@"
        r"(?!(?:users\.noreply\.github\.com|example\.(?:com|org|net))\b)"
        r"[A-Z0-9.\-]+\.[A-Z]{2,}\b"
    ),
}
MAX_FILE_BYTES = 5 * 1024 * 1024
FORBIDDEN_RELEASE_SUFFIXES = {".xlsx", ".xls", ".xlsm", ".ods"}
FORBIDDEN_RELEASE_NAME_FRAGMENTS = {
    "private_id_map",
    "release_id_salt",
    "annotation_workbook",
    "discussion",
    "intermediate",
    "manual_review",
    "notes",
    "report",
    "workbook",
}
SPECIALIZED_DATA_ROOTS = {"benchmark", "training"}
POLICY_LITERAL_EXEMPTIONS = {
    Path("scripts/verify_benchmark.py"): {"local_user_path"},
}


def private_denylist() -> tuple[str, ...]:
    """Load private identity terms without embedding them in the release."""
    raw = os.environ.get("VERICLAIM_PRIVATE_DENYLIST", "")
    return tuple(term.strip().casefold() for term in raw.split(",") if term.strip())


def verify_git_metadata(errors: list[str]) -> None:
    """Require neutral commit identities when running inside a Git checkout."""
    if not (ROOT / ".git").exists():
        return
    result = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "log",
            "--format=%an%x00%ae%x00%cn%x00%ce",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    for index, line in enumerate(result.stdout.splitlines(), 1):
        author_name, author_email, committer_name, committer_email = line.split("\x00")
        for role, name in (
            ("author", author_name),
            ("committer", committer_name),
        ):
            normalized = name.casefold()
            if "anonymous" not in normalized and "paper" not in normalized:
                errors.append(f"non-neutral Git {role} name in commit {index}")
        for role, email in (
            ("author", author_email),
            ("committer", committer_email),
        ):
            if not email.casefold().endswith("@users.noreply.github.com"):
                errors.append(f"non-neutral Git {role} email in commit {index}")


def iter_release_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed in the release: {relative}")
        if path.is_file():
            files.append(path)
    return sorted(files)


def verify_specialized_gates(errors: list[str]) -> None:
    for script in (
        "scripts/verify_benchmark.py",
        "scripts/verify_training_data.py",
        "scripts/verify_submission_scope.py",
    ):
        result = subprocess.run(
            [sys.executable, script],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            details = (result.stdout + result.stderr).strip().replace("\n", " ")
            errors.append(f"specialized gate failed ({script}): {details[:500]}")


def verify_manifest(files: list[Path], errors: list[str]) -> None:
    manifest_path = ROOT / "RELEASE_MANIFEST.json"
    if not manifest_path.is_file():
        errors.append("missing repository release manifest")
        return
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    listed = {item["path"]: item for item in payload.get("files", [])}
    actual = {
        str(path.relative_to(ROOT)): path
        for path in files
        if path != manifest_path
    }
    if set(listed) != set(actual):
        missing = sorted(set(actual) - set(listed))
        extra = sorted(set(listed) - set(actual))
        errors.append(f"release manifest file-set mismatch: missing={missing} extra={extra}")
        return
    import hashlib

    for relative, path in actual.items():
        item = listed[relative]
        size = path.stat().st_size
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if int(item.get("bytes", -1)) != size:
            errors.append(f"release manifest byte mismatch: {relative}")
        if item.get("sha256") != digest:
            errors.append(f"release manifest hash mismatch: {relative}")


def main() -> int:
    errors: list[str] = []
    identity_terms = private_denylist()
    files = iter_release_files()
    for path in files:
        relative = path.relative_to(ROOT)
        lowered_path = str(relative).casefold()
        size = path.stat().st_size
        if path.suffix.casefold() in FORBIDDEN_RELEASE_SUFFIXES:
            errors.append(f"annotation workbook is not releasable: {relative}")
        if any(fragment in lowered_path for fragment in FORBIDDEN_RELEASE_NAME_FRAGMENTS):
            errors.append(f"private release asset name: {relative}")
        if size > MAX_FILE_BYTES:
            errors.append(f"oversized file ({size} bytes): {relative}")
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {
            "Dockerfile",
            "LICENSE",
            "Makefile",
            ".gitignore",
        }:
            errors.append(f"unexpected binary or extension: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        # The release checker necessarily contains literal examples of every
        # forbidden pattern. Scan all other release files against that policy.
        uses_specialized_privacy_gate = (
            bool(relative.parts) and relative.parts[0] in SPECIALIZED_DATA_ROOTS
        )
        if relative != Path("scripts/verify_release.py") and not uses_specialized_privacy_gate:
            for label, pattern in FORBIDDEN_PATTERNS.items():
                if label in POLICY_LITERAL_EXEMPTIONS.get(relative, set()):
                    continue
                if pattern.search(text):
                    errors.append(f"{label}: {relative}")
        folded = text.casefold()
        for term in identity_terms:
            if term in folded:
                errors.append(f"private_identity_term: {relative}")

    required = [
        "README.md",
        "Dockerfile",
        "data/runtime_scenarios.jsonl",
        "data/paper_metrics.json",
        "benchmark/vericlaim_sec/release_manifest.json",
        "training/vericlaim_sec/release_manifest.json",
        "scripts/verify_benchmark.py",
        "scripts/verify_training_data.py",
        "scripts/run_eev.py",
        "scripts/run_pase.py",
        "scripts/reproduce_paper_metrics.py",
        "scripts/verify_submission_scope.py",
        "scripts/run_all.py",
    ]
    for relative in required:
        if not (ROOT / relative).is_file():
            errors.append(f"missing required file: {relative}")

    verify_specialized_gates(errors)
    verify_manifest(files, errors)
    verify_git_metadata(errors)

    report = {
        "status": "PASS" if not errors else "FAIL",
        "files_checked": len(files),
        "errors": errors,
    }
    output = ROOT / "outputs/release_gate.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

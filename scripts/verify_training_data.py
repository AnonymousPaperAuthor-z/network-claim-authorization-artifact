#!/usr/bin/env python3
"""Verify anonymous EEV/PASE training views and supervision provenance."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from verify_benchmark import check_evidence_privacy, valid_ipv4


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TRAINING = ROOT / "training/vericlaim_sec"
EXPECTED = {
    "eev_train": 45_114,
    "eev_transfer": 1_067,
    "eev_contrastive_pairs": 17,
    "pase_units": 27_292,
}
EEV_ATTRIBUTES = {"brand", "model", "firmware_version", "any"}
ALLOWED_EEV_FIELDS = {
    "schema_version",
    "example_id",
    "record_id",
    "partition",
    "split",
    "attribute",
    "candidate_value",
    "field_path",
    "source_type_observed",
    "section",
    "exact_span",
    "local_context",
    "span_sha256",
    "source_role",
    "subject_role",
    "support_type",
    "confusion_risk",
    "authorized_for_attribute",
    "terminal_eligibility",
    "label_masks",
    "label_source",
}
ALLOWED_PAIR_FIELDS = {
    "schema_version",
    "pair_id",
    "left_example_id",
    "right_example_id",
    "relation",
    "left_subject_role",
    "right_subject_role",
}
ALLOWED_PASE_FIELDS = {
    "schema_version",
    "unit_id",
    "record_id",
    "split",
    "source_type",
    "marker",
    "parent_section",
    "text",
    "text_sha256",
    "labels",
    "label_mask",
    "label_names",
    "mandatory",
    "supervision_contract",
}
FORBIDDEN_FIELD_FRAGMENTS = {
    "gold",
    "manual",
    "annotator",
    "reviewer_note",
    "ip_address",
    "endpoint_port",
    "original_record_id",
}


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"non-object at {path}:{line_no}")
            yield row


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_fields(
    row: dict[str, Any],
    allowed: set[str],
    errors: list[str],
    label: str,
) -> None:
    unknown = set(row) - allowed
    if unknown:
        errors.append(f"unknown release fields {sorted(unknown)}: {label}")
    for field in row:
        lowered = field.casefold()
        if any(fragment in lowered for fragment in FORBIDDEN_FIELD_FRAGMENTS):
            errors.append(f"forbidden release field {field!r}: {label}")


def check_value(value: str, errors: list[str], label: str, allow_version: bool) -> None:
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return
    if not allow_version and not value.startswith("<REDACTED_"):
        errors.append(f"address-shaped released value {value!r}: {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training", type=Path, default=DEFAULT_TRAINING)
    args = parser.parse_args()
    root = args.training
    errors: list[str] = []
    manifest_path = root / "release_manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"missing training manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    listed: set[Path] = set()
    manifest_rows = 0
    for item in manifest.get("files", []):
        path = root / item["path"]
        listed.add(path)
        if not path.is_file():
            errors.append(f"missing shard: {item['path']}")
            continue
        if path.stat().st_size != int(item["bytes"]):
            errors.append(f"byte count mismatch: {item['path']}")
        if sha256(path) != item["sha256"]:
            errors.append(f"SHA-256 mismatch: {item['path']}")
        rows = sum(1 for _ in iter_jsonl(path))
        manifest_rows += rows
        if rows != int(item["rows"]):
            errors.append(f"row count mismatch: {item['path']}")
    actual = set((root / "eev").glob("*.jsonl")) | set(
        (root / "pase").glob("*.jsonl")
    )
    if listed != actual:
        errors.append("manifest shard set differs from on-disk shard set")

    examples: set[str] = set()
    pairs: list[dict[str, Any]] = []
    counts = Counter()
    label_sources = Counter()
    for path in sorted((root / "eev").glob("*.jsonl")):
        for row in iter_jsonl(path):
            schema = row.get("schema_version")
            if schema == "vericlaim-training-v1-eev-pair":
                check_fields(row, ALLOWED_PAIR_FIELDS, errors, str(row.get("pair_id")))
                pairs.append(row)
                counts["eev_contrastive_pairs"] += 1
                continue
            if schema != "vericlaim-training-v1-eev":
                errors.append(f"unknown EEV schema: {path.name}")
                continue
            check_fields(
                row, ALLOWED_EEV_FIELDS, errors, str(row.get("example_id"))
            )
            example_id = str(row.get("example_id", ""))
            if not example_id.startswith("EEV-") or example_id in examples:
                errors.append(f"invalid or duplicate EEV example: {example_id}")
            examples.add(example_id)
            partition = str(row.get("partition", ""))
            count_key = (
                "eev_transfer"
                if partition == "evidence_rich_transfer"
                else "eev_train"
            )
            counts[count_key] += 1
            attribute = str(row.get("attribute", ""))
            if attribute not in EEV_ATTRIBUTES:
                errors.append(f"unknown EEV attribute: {example_id}")
            label_source = str(row.get("label_source", ""))
            if not label_source:
                errors.append(f"missing EEV label_source: {example_id}")
            label_sources[label_source] += 1
            candidate = str(row.get("candidate_value", ""))
            check_value(
                candidate,
                errors,
                example_id,
                allow_version=attribute == "firmware_version",
            )
            allowed_versions = (
                {candidate}
                if attribute == "firmware_version" and candidate
                else set()
            )
            allowed_identities = {candidate} if candidate else set()
            for field in ("exact_span", "local_context", "field_path"):
                check_evidence_privacy(
                    str(row.get(field, "")),
                    allowed_version_values=allowed_versions,
                    allowed_identity_values=allowed_identities,
                    allow_standalone_version=field == "exact_span",
                    errors=errors,
                    label=f"{example_id}/{field}",
                )
            exact_span = str(row.get("exact_span", ""))
            if hashlib.sha256(exact_span.encode("utf-8")).hexdigest() != row.get(
                "span_sha256"
            ):
                errors.append(f"EEV span digest mismatch: {example_id}")

    for row in pairs:
        pair_id = str(row.get("pair_id", ""))
        if row.get("left_example_id") not in examples:
            errors.append(f"unknown left EEV example: {pair_id}")
        if row.get("right_example_id") not in examples:
            errors.append(f"unknown right EEV example: {pair_id}")

    units: set[str] = set()
    for path in sorted((root / "pase").glob("*.jsonl")):
        for row in iter_jsonl(path):
            counts["pase_units"] += 1
            check_fields(
                row, ALLOWED_PASE_FIELDS, errors, str(row.get("unit_id"))
            )
            unit_id = str(row.get("unit_id", ""))
            if not unit_id.startswith("PASE-") or unit_id in units:
                errors.append(f"invalid or duplicate PASE unit: {unit_id}")
            units.add(unit_id)
            if row.get("supervision_contract") != "weak_or_heuristic_not_adjudicated_gold":
                errors.append(f"PASE supervision upgraded to gold: {unit_id}")
            labels = row.get("labels") or []
            masks = row.get("label_mask") or []
            names = row.get("label_names") or []
            if not (len(labels) == len(masks) == len(names) == 4):
                errors.append(f"PASE label shape mismatch: {unit_id}")
            text = str(row.get("text", ""))
            check_evidence_privacy(
                text,
                allowed_version_values=set(),
                allowed_identity_values=set(),
                errors=errors,
                label=f"{unit_id}/text",
            )
            if hashlib.sha256(text.encode("utf-8")).hexdigest() != row.get(
                "text_sha256"
            ):
                errors.append(f"PASE text digest mismatch: {unit_id}")

    for key, expected in EXPECTED.items():
        if counts[key] != expected:
            errors.append(f"{key}: {counts[key]} != {expected}")
    if "Only benchmark gold_values" not in str(manifest.get("gold_contract")):
        errors.append("training manifest does not preserve the gold boundary")
    if "Privacy-filtered subset" not in str(
        manifest.get("public_training_subset")
    ):
        errors.append("training manifest does not identify the public subset boundary")

    report = {
        "status": "PASS" if not errors else "FAIL",
        "counts": dict(counts),
        "label_sources": dict(sorted(label_sources.items())),
        "manifest_rows": manifest_rows,
        "errors": errors,
    }
    output = ROOT / "outputs/training_data_gate.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

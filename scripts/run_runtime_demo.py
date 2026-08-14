#!/usr/bin/env python3
"""Run the standalone VeriClaim state machine on synthetic scenarios."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from probeagent.knowledge.identity_completion import IdentityKnowledgeBase
from probeagent.policy.runtime import (
    AcquisitionRequest,
    PostAcquisitionDecision,
    run_claim,
)


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(f"{path}:{line_number}: expected a JSON object")
                yield row


def execute(row: dict[str, Any], kb: IdentityKnowledgeBase) -> dict[str, Any]:
    acquisition = row.get("acquisition_request")
    post_acquisition = row.get("post_acquisition_decision")
    trace = run_claim(
        record_id=row["scenario_id"],
        attribute=row["attribute"],
        candidate_value=row.get("candidate_value", ""),
        evidence_context=row.get("evidence_context", ""),
        verifier_accept=bool(row.get("verifier_accept")),
        verifier_reason=row.get("verifier_reason", ""),
        observed_triplet=row.get("observed_triplet") or {},
        role_valid=bool(row.get("role_valid", True)),
        coarse_value=row.get("coarse_value", ""),
        coarse_value_supported=bool(row.get("coarse_value_supported")),
        acquisition_request=AcquisitionRequest(**acquisition) if acquisition else None,
        acquired_evidence=row.get("acquired_evidence", ""),
        post_acquisition_decision=(
            PostAcquisitionDecision(**post_acquisition) if post_acquisition else None
        ),
        identity_kb=kb if row.get("use_identity_kb") else None,
        semantic_assertions=row.get("semantic_assertions") or [],
    )
    result = trace.to_dict()
    result["scenario_id"] = row["scenario_id"]
    result["expected_action"] = row["expected_action"]
    return result


def validate(row: dict[str, Any], result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if result["terminal_action"] != row["expected_action"]:
        errors.append(
            f"action expected={row['expected_action']} actual={result['terminal_action']}"
        )
    if "expected_value" in row and result["terminal_value"] != row["expected_value"]:
        errors.append(
            f"value expected={row['expected_value']!r} actual={result['terminal_value']!r}"
        )
    if "expected_provenance" in row:
        if result["terminal_provenance"] != row["expected_provenance"]:
            errors.append(
                "provenance "
                f"expected={row['expected_provenance']!r} "
                f"actual={result['terminal_provenance']!r}"
            )
    if "expected_reason_prefix" in row:
        if not result["terminal_reason"].startswith(row["expected_reason_prefix"]):
            errors.append(
                "reason "
                f"expected_prefix={row['expected_reason_prefix']!r} "
                f"actual={result['terminal_reason']!r}"
            )
    if "expected_kb_reason" in row:
        if result.get("knowledge_completion", {}).get("reason") != row["expected_kb_reason"]:
            errors.append(
                "kb_reason "
                f"expected={row['expected_kb_reason']!r} "
                f"actual={result.get('knowledge_completion', {}).get('reason')!r}"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        default=ROOT / "data/runtime_scenarios.jsonl",
    )
    parser.add_argument(
        "--kb",
        type=Path,
        default=ROOT / "data/synthetic_identity_kb.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "outputs/runtime_demo.jsonl",
    )
    args = parser.parse_args()

    kb = IdentityKnowledgeBase.from_path(args.kb)
    rows = list(iter_jsonl(args.input))
    results: list[dict[str, Any]] = []
    failures: list[str] = []
    for row in rows:
        result = execute(row, kb)
        errors = validate(row, result)
        result["validation_errors"] = errors
        results.append(result)
        failures.extend(f"{row['scenario_id']}: {error}" for error in errors)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n")

    summary = {
        "scenarios": len(results),
        "failures": len(failures),
        "actions": dict(sorted(Counter(row["terminal_action"] for row in results).items())),
        "output": str(args.output.relative_to(ROOT)),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

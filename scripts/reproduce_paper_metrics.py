#!/usr/bin/env python3
"""Recompute paper metrics from released aggregate integer counts."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data/paper_metrics.json"
OUTPUT = ROOT / "outputs/paper_metrics.json"


def divide(numerator: int | float, denominator: int | float) -> float:
    if denominator <= 0:
        raise ValueError("metric denominator must be positive")
    return numerator / denominator


def binomial_cdf(k: int, n: int, p: float) -> float:
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0 if k < n else 1.0
    logs = [
        math.lgamma(n + 1)
        - math.lgamma(i + 1)
        - math.lgamma(n - i + 1)
        + i * math.log(p)
        + (n - i) * math.log1p(-p)
        for i in range(k + 1)
    ]
    largest = max(logs)
    if largest < -745.0:
        return 0.0
    return math.exp(largest) * sum(math.exp(value - largest) for value in logs)


def cp_upper(events: int, trials: int, alpha: float = 0.05) -> float:
    if not 0 <= events <= trials or trials <= 0:
        raise ValueError("expected 0 <= events <= trials and trials > 0")
    if events == trials:
        return 1.0
    low, high = 0.0, 1.0
    for _ in range(90):
        midpoint = (low + high) / 2.0
        if binomial_cdf(events, trials, midpoint) > alpha:
            low = midpoint
        else:
            high = midpoint
    return high


def binary_metrics(row: dict[str, Any]) -> dict[str, float | None]:
    tp, fp, tn, fn = (int(row[key]) for key in ("tp", "fp", "tn", "fn"))
    precision = divide(tp, tp + fp)
    recall = divide(tp, tp + fn)
    specificity = divide(tn, tn + fp)
    accuracy = divide(tp + tn, tp + fp + tn + fn)
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {
        "precision": precision,
        "recall": recall,
        "f1": divide(2 * precision * recall, precision + recall),
        "accuracy": accuracy,
        "fpr": 1.0 - specificity,
        "balanced_accuracy": (recall + specificity) / 2.0,
        "mcc": divide(tp * tn - fp * fn, denominator) if denominator else None,
        "accepted_error": divide(fp, tp + fp),
        "u95": cp_upper(fp, tp + fp),
    }


def action_metrics(row: dict[str, Any]) -> dict[str, float]:
    return {
        "accepted_error": divide(row["false"], row["accepted"]),
        "u95": cp_upper(row["false"], row["accepted"]),
        "useful_value_resolution": divide(row["useful_resolved"], row["supported"]),
    }


def main() -> int:
    payload = json.loads(INPUT.read_text(encoding="utf-8"))
    failures: list[str] = []
    result: dict[str, Any] = {
        "schema_version": payload["schema_version"],
        "candidate_verification": {},
        "eev_transfer": {},
        "terminal_outcomes": {},
        "component_ablation": {},
        "csda": {},
        "robustness": {},
        "composition": {},
        "cve": {},
        "pase": {},
    }

    for row in payload["candidate_verification"]:
        metrics = binary_metrics(row)
        result["candidate_verification"][row["id"]] = metrics
        if abs(metrics["u95"] - row["reported_u95"]) > 1e-9:
            failures.append(f"{row['id']}: candidate U95 mismatch")

    for section in ("eev_transfer", "terminal_outcomes", "component_ablation"):
        for row in payload[section]:
            if row["correct_accepted"] + row["false"] != row["accepted"]:
                failures.append(f"{row['id']}: accepted count mismatch")
            metrics = action_metrics(row)
            if "unsafe_candidates" in row:
                metrics["unsafe_candidate_suppression"] = divide(
                    row["unsafe_suppressed"], row["unsafe_candidates"]
                )
            result[section][row["id"]] = metrics
            if abs(metrics["u95"] - row["reported_u95"]) > 1e-9:
                failures.append(f"{row['id']}: action U95 mismatch")

    csda = payload["csda"]
    for row in csda["auc_rows"]:
        if not 0.0 <= row["evidence_state_auc"] <= 1.0:
            failures.append(f"{row['id']}: invalid evidence-state AUC")
        if not 0.0 <= row["with_csda_auc"] <= 1.0:
            failures.append(f"{row['id']}: invalid CSDA AUC")
        result["csda"][row["id"]] = {
            "auc_gain": row["with_csda_auc"] - row["evidence_state_auc"]
        }
    multiplicity = csda["natural_source_multiplicity"]
    if (
        multiplicity["at_most_one"]
        + multiplicity["exactly_two"]
        + multiplicity["three_or_more"]
        != multiplicity["claims"]
    ):
        failures.append("CSDA source-multiplicity partition mismatch")

    for row in payload["robustness"]:
        result["robustness"][row["id"]] = {
            "conditional_detection": divide(
                row["conditional_detected"], row["eligible_clean_pass"]
            ),
            "attack_rejection": divide(row["attacks_rejected"], row["pairs"]),
            "clean_acceptance": divide(row["clean_values_accepted"], row["pairs"]),
            "balanced_accuracy": (
                divide(row["attacks_rejected"], row["pairs"])
                + divide(row["clean_values_accepted"], row["pairs"])
            ) / 2.0,
        }

    for row in payload["composition"]:
        result["composition"][row["id"]] = {
            "precision": divide(row["correct"], row["emitted"]),
            "supported_recall": divide(row["correct"], row["supported"]),
        }

    controlled = payload["cve"]["controlled_evasion"]
    normal = payload["cve"]["reviewed_normal_task"]
    result["cve"] = {
        "perturbations_intercepted": divide(
            controlled["intercepted"], controlled["successful_perturbations"]
        ),
        "affected_endpoints_fully_protected": divide(
            controlled["fully_protected_endpoints"], controlled["affected_endpoints"]
        ),
        "associations_preserved": divide(
            controlled["associations_preserved"], controlled["association_instances"]
        ),
        "endpoint_cve_pairs_robust": divide(
            controlled["robust_endpoint_cve_pairs"], controlled["endpoint_cve_pairs"]
        ),
        "candidate_matched_recall_retained": divide(
            normal["protected_true_links"], normal["candidate_true_links"]
        ),
        "candidate_false_link_rate": divide(
            normal["candidate_false_links"],
            normal["candidate_true_links"] + normal["candidate_false_links"],
        ),
        "protected_false_link_rate": divide(
            normal["protected_false_links"],
            normal["protected_true_links"] + normal["protected_false_links"],
        ),
    }

    pase = payload["pase"]
    result["pase"]["serialization_fidelity"] = {
        row["id"]: divide(row["matched"], row["eligible"])
        for row in pase["serialization_fidelity"]
    }
    model_diverse = pase["model_diverse_firmware"]
    static_rich = pase["static_rich_firmware"]
    prompt_tokens = pase["prompt_tokens"]
    result["pase"]["model_diverse_firmware_gain_pp"] = 100.0 * divide(
        model_diverse["pase_correct"] - model_diverse["fixed_head_tail_correct"],
        model_diverse["records"],
    )
    result["pase"]["static_rich_firmware_gain_pp"] = 100.0 * divide(
        static_rich["pase_strict"] - static_rich["fixed_head_tail_strict"],
        static_rich["observed_records"],
    )
    result["pase"]["prompt_token_reduction"] = 1.0 - divide(
        prompt_tokens["pase_mean"], prompt_tokens["complete_mean"]
    )

    result["validation_errors"] = failures
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "status": "PASS" if not failures else "FAIL",
                "candidate_verifiers": len(payload["candidate_verification"]),
                "metric_sections": 9,
                "errors": failures,
                "output": str(OUTPUT.relative_to(ROOT)),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

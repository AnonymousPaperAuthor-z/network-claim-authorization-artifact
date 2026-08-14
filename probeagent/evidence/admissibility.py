"""Evidence source admissibility matrix for VeriClaim.

The matrix is deliberately declarative: source-type and attribute admissibility
rules live in ``config/evidence_admissibility_matrix.json`` so new evidence
types can be added without changing policy code. Unknown sources remain
conservative and are not admitted for direct acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX_PATH = PROJECT_ROOT / "config" / "evidence_admissibility_matrix.json"
ACCEPT_DECISIONS = {"authorized", "weak_authorized"}


def clean(value: Any, default: str = "") -> str:
    text = " ".join(str(value or "").replace("\x00", "").strip().split())
    return text if text else default


def norm(value: Any, default: str = "") -> str:
    text = clean(value, default=default).lower()
    return text if text else default


@dataclass(frozen=True)
class AdmissibilityDecision:
    source_type: str
    attribute: str
    decision: str
    rule_id: str
    reason: str
    matrix_version: str
    blocked_by: tuple[str, ...] = ()
    unknown_source: bool = False
    unknown_attribute: bool = False

    @property
    def direct_accept_authorized(self) -> bool:
        return self.decision in ACCEPT_DECISIONS and not self.blocked_by

    @property
    def requires_semantic_contract(self) -> bool:
        return self.decision == "conditional"


@lru_cache(maxsize=1)
def load_admissibility_matrix(path: str | None = None) -> dict[str, Any]:
    matrix_path = Path(path) if path else DEFAULT_MATRIX_PATH
    with matrix_path.open("r", encoding="utf-8") as handle:
        matrix = json.load(handle)
    if not isinstance(matrix, dict):
        raise ValueError(f"admissibility matrix must be a JSON object: {matrix_path}")
    if "source_types" not in matrix or not isinstance(matrix["source_types"], dict):
        raise ValueError(f"admissibility matrix missing source_types: {matrix_path}")
    return matrix


def _default_decision(matrix: Mapping[str, Any]) -> Mapping[str, Any]:
    default = matrix.get("default_decision")
    if isinstance(default, Mapping):
        return default
    return {
        "decision": "not_authorized",
        "rule_id": "EAM-DEFAULT-UNKNOWN",
        "reason": "Unknown source or attribute is not admitted for direct acceptance.",
    }


def source_types(matrix: Mapping[str, Any] | None = None) -> set[str]:
    data = matrix or load_admissibility_matrix()
    return set((data.get("source_types") or {}).keys())


def sources_with_risk_tag(tag: str, matrix: Mapping[str, Any] | None = None) -> set[str]:
    data = matrix or load_admissibility_matrix()
    out: set[str] = set()
    for source, spec in (data.get("source_types") or {}).items():
        tags = spec.get("risk_tags") if isinstance(spec, Mapping) else []
        if tag in set(tags or []):
            out.add(str(source))
    return out


def sources_for_attribute(
    attribute: str,
    *,
    accepted_decisions: set[str] | None = None,
    matrix: Mapping[str, Any] | None = None,
) -> set[str]:
    data = matrix or load_admissibility_matrix()
    decisions = accepted_decisions or ACCEPT_DECISIONS
    attr = norm(attribute)
    out: set[str] = set()
    for source, spec in (data.get("source_types") or {}).items():
        if not isinstance(spec, Mapping):
            continue
        rules = spec.get("attribute_rules")
        if not isinstance(rules, Mapping):
            continue
        rule = rules.get(attr)
        if isinstance(rule, Mapping) and norm(rule.get("decision")) in decisions:
            out.add(str(source))
    return out


def evaluate_admissibility(
    source_type: str,
    attribute: str,
    *,
    flags: Mapping[str, bool] | None = None,
    matrix: Mapping[str, Any] | None = None,
) -> AdmissibilityDecision:
    data = matrix or load_admissibility_matrix()
    version = clean(data.get("version"), "unknown")
    source = norm(source_type, "unknown")
    attr = norm(attribute, "unknown")
    source_specs = data.get("source_types") or {}
    default = _default_decision(data)
    spec = source_specs.get(source)
    unknown_source = not isinstance(spec, Mapping)
    unknown_attribute = False
    if unknown_source:
        rule = default
    else:
        rules = spec.get("attribute_rules")
        if not isinstance(rules, Mapping) or attr not in rules:
            rule = default
            unknown_attribute = True
        else:
            rule = rules[attr]
            if not isinstance(rule, Mapping):
                rule = default
                unknown_attribute = True
    decision = norm(rule.get("decision"), "not_authorized")
    rule_id = clean(rule.get("rule_id"), clean(default.get("rule_id"), "EAM-DEFAULT-UNKNOWN"))
    reason = clean(rule.get("reason"), clean(default.get("reason"), "Unknown source or attribute."))
    true_flags = {key for key, value in (flags or {}).items() if bool(value)}
    blocked = tuple(flag for flag in (rule.get("blocked_by") or []) if flag in true_flags)
    if blocked:
        decision = "not_authorized"
        rule_id = f"{rule_id}:BLOCKED"
        reason = f"{reason} Blocked by: {', '.join(blocked)}."
    return AdmissibilityDecision(
        source_type=source,
        attribute=attr,
        decision=decision,
        rule_id=rule_id,
        reason=reason,
        matrix_version=version,
        blocked_by=blocked,
        unknown_source=unknown_source,
        unknown_attribute=unknown_attribute,
    )

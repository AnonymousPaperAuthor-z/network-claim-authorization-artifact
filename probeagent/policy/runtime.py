"""Traceable terminal decision runtime for VeriClaim."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from probeagent.evidence.candidate_shape_guard import evaluate_candidate_shape
from probeagent.evidence.identity_assertions import detect_identity_conflicts
from probeagent.knowledge.identity_completion import IdentityKnowledgeBase


TERMINAL_ACTIONS = {"ACCEPT", "REDUCE_GRANULARITY", "ESCALATE", "ABSTAIN"}
ACQUISITION_ACTIONS = {
    "ACQUIRE_PROTOCOL_INFO",
    "ACQUIRE_STATIC_INFO",
    "ACQUIRE_EXTERNAL_INFO",
}


def clean(value: Any) -> str:
    return " ".join(str(value or "").replace("\x00", " ").split()).strip()


@dataclass(frozen=True)
class AcquisitionRequest:
    action: str
    target: str
    required_observables: tuple[str, ...] = ()
    executor: str = ""
    expected_utility: float | None = None


@dataclass(frozen=True)
class PostAcquisitionDecision:
    action: str
    value: str = ""
    verifier: str = ""
    evidence_source: str = ""
    rationale: str = ""
    observation_id: str = ""


@dataclass
class RuntimeTrace:
    record_id: str
    attribute: str
    candidate_value: str
    verifier_accept: bool
    verifier_reason: str
    terminal_action: str = ""
    terminal_value: str = ""
    terminal_provenance: str = ""
    terminal_reason: str = ""
    stages: list[dict[str, Any]] = field(default_factory=list)
    shape_contract: dict[str, Any] = field(default_factory=dict)
    conflict_contract: dict[str, Any] = field(default_factory=dict)
    knowledge_completion: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_claim(
    *,
    record_id: str,
    attribute: str,
    candidate_value: str,
    evidence_context: str,
    verifier_accept: bool,
    verifier_reason: str,
    observed_triplet: dict[str, str] | None = None,
    role_valid: bool = True,
    coarse_value: str = "",
    coarse_value_supported: bool = False,
    acquisition_request: AcquisitionRequest | None = None,
    acquired_evidence: str = "",
    post_acquisition_decision: PostAcquisitionDecision | None = None,
    identity_kb: IdentityKnowledgeBase | None = None,
    semantic_assertions: list[Mapping[str, Any]] | None = None,
) -> RuntimeTrace:
    """Route one candidate to a terminal decision or pending acquisition."""

    candidate = clean(candidate_value)
    attribute = clean(attribute)
    trace = RuntimeTrace(
        record_id=clean(record_id),
        attribute=attribute,
        candidate_value=candidate,
        verifier_accept=bool(verifier_accept),
        verifier_reason=clean(verifier_reason),
    )
    trace.stages.append(
        {
            "stage": "VERIFY_CANDIDATE",
            "candidate_value": candidate,
            "accepted": bool(verifier_accept),
            "reason": clean(verifier_reason),
        }
    )

    shape = evaluate_candidate_shape(attribute, candidate)
    trace.shape_contract = {
        "blocked": shape.blocked,
        "reason": shape.reason,
        "recommended_action": shape.recommended_action,
    }
    trace.stages.append({"stage": "SHAPE_CONTRACT", **trace.shape_contract})
    eligible = bool(verifier_accept) and not shape.blocked

    cumulative_evidence = evidence_context
    if acquired_evidence:
        cumulative_evidence += f"\n[ACQUIRED_EVIDENCE]\n{acquired_evidence}"
    conflict = detect_identity_conflicts(
        cumulative_evidence,
        additional_brands=identity_kb.brand_names if identity_kb else (),
        semantic_assertions=semantic_assertions or (),
    )
    trace.conflict_contract = conflict
    hard_conflict = attribute in conflict["conflicting_attributes"]
    if hard_conflict:
        trace.terminal_action = "ESCALATE"
        trace.terminal_reason = "LOCATABLE_COMPETING_IDENTITY_ASSERTIONS"
        return trace

    if eligible and candidate:
        trace.terminal_action = "ACCEPT"
        trace.terminal_value = candidate
        trace.terminal_provenance = "DIRECT_AUTHORIZED_EVIDENCE"
        trace.terminal_reason = "VERIFIER_AND_CONTRACTS_ACCEPT"
        return trace

    if coarse_value_supported and clean(coarse_value):
        trace.terminal_action = "REDUCE_GRANULARITY"
        trace.terminal_value = clean(coarse_value)
        trace.terminal_provenance = "DIRECT_AUTHORIZED_COARSE_VALUE"
        trace.terminal_reason = "SUPPORTED_COARSE_VALUE"
        return trace

    if identity_kb is not None:
        completion = identity_kb.complete(
            target_attribute=attribute,
            observed=observed_triplet or {},
            evidence_context=cumulative_evidence,
            role_valid=role_valid,
            has_identity_conflict=hard_conflict,
        )
        trace.knowledge_completion = completion.to_dict()
        if completion.accepted:
            trace.terminal_action = "ACCEPT"
            trace.terminal_value = completion.derived_value
            trace.terminal_provenance = completion.provenance
            trace.terminal_reason = completion.reason
            return trace
        if completion.status == "ESCALATE":
            trace.terminal_action = "ESCALATE"
            trace.terminal_reason = completion.reason
            return trace

    if acquired_evidence:
        if post_acquisition_decision is None:
            trace.terminal_action = "ABSTAIN"
            trace.terminal_reason = "ACQUIRED_EVIDENCE_NOT_REVERIFIED"
            return trace
        action = clean(post_acquisition_decision.action).upper()
        value = clean(post_acquisition_decision.value)
        if action not in TERMINAL_ACTIONS:
            raise ValueError(f"post-acquisition action must be terminal: {action!r}")
        if action in {"ACCEPT", "REDUCE_GRANULARITY"} and not value:
            raise ValueError(f"{action} requires a nonempty value")
        trace.terminal_action = action
        trace.terminal_value = value
        trace.terminal_provenance = "POST_ACQUISITION_REVERIFIED"
        trace.terminal_reason = clean(post_acquisition_decision.rationale) or action
        return trace

    if acquisition_request is not None:
        action = clean(acquisition_request.action).upper()
        if action not in ACQUISITION_ACTIONS:
            raise ValueError(f"unsupported acquisition action: {action!r}")
        if not clean(acquisition_request.target) or not clean(acquisition_request.executor):
            raise ValueError("acquisition requires a target and executable provider")
        trace.terminal_action = action
        trace.terminal_reason = "PENDING_EVIDENCE_ACQUISITION"
        trace.stages.append({"stage": "ACQUIRE", **asdict(acquisition_request)})
        return trace

    trace.terminal_action = "ABSTAIN"
    trace.terminal_reason = (
        f"SHAPE_CONTRACT_REJECT:{shape.reason}"
        if shape.blocked
        else "NO_SAFE_VALUE_OR_EXECUTABLE_EVIDENCE_PATH"
    )
    return trace

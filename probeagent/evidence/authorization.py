"""Deterministic authorization contracts around the learned EEV decision."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from probeagent.evidence.admissibility import evaluate_admissibility
from probeagent.evidence.field_path_authorization_guard import (
    evaluate_field_path_authorization,
)
from probeagent.evidence.static_resource_verifier import (
    evaluate_static_resource_firmware,
)


@dataclass(frozen=True)
class AuthorizationDecision:
    authorized: bool
    reason: str
    rule_id: str
    source_type: str
    attribute: str
    field_path_blocked: bool = False
    static_contract: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def authorize_claim(
    *,
    attribute: str,
    candidate_value: str,
    source_type: str,
    field_path: str = "",
    risk_flags: Mapping[str, bool] | None = None,
    evidence_row: Mapping[str, Any] | None = None,
) -> AuthorizationDecision:
    """Apply attribute, field, source, and static-resource contracts.

    EEV estimates semantic entitlement. This function implements only the
    explicit constraints that model confidence cannot override.
    """

    field_decision = evaluate_field_path_authorization(
        attribute,
        field_path,
        source_type=source_type,
    )
    if field_decision.blocked:
        return AuthorizationDecision(
            False,
            field_decision.reason,
            "FIELD-PATH-CONTRACT",
            source_type,
            attribute,
            field_path_blocked=True,
        )

    matrix_decision = evaluate_admissibility(
        source_type,
        attribute,
        flags=risk_flags,
    )
    if matrix_decision.requires_semantic_contract:
        if source_type != "static_resource" or attribute != "firmware_version":
            return AuthorizationDecision(
                False,
                matrix_decision.reason,
                matrix_decision.rule_id,
                source_type,
                attribute,
            )
        static_row = dict(evidence_row or {})
        static_row["candidate_value"] = candidate_value
        static_decision = evaluate_static_resource_firmware(static_row)
        return AuthorizationDecision(
            static_decision.direct_accept_candidate,
            static_decision.reason,
            matrix_decision.rule_id,
            source_type,
            attribute,
            static_contract=static_decision.as_dict(),
        )

    return AuthorizationDecision(
        matrix_decision.direct_accept_authorized,
        matrix_decision.reason,
        matrix_decision.rule_id,
        source_type,
        attribute,
    )

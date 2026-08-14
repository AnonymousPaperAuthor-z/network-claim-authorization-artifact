"""Deterministic terminal router for an EEV decision state."""

from __future__ import annotations

from dataclasses import dataclass

from probeagent.policy.action_ontology import ManualAction


@dataclass(frozen=True)
class RoutingSignals:
    exact_value_supported: bool = False
    candidate_locatable: bool = False
    attribute_role_valid: bool = False
    source_authorized: bool = False
    coarse_value_supported: bool = False
    candidate_wrong_role: bool = False

    explicit_conflict_count: int = 0
    cross_vendor_conflict: bool = False
    authenticity_doubt: bool = False

    protocol_endpoint_observed: bool = False
    protocol_probe_returns_target: bool = False
    protocol_expected_utility: float = 0.0

    static_endpoint_observed: bool = False
    static_path_device_linked: bool = False
    temporal_match_possible: bool = False
    static_expected_utility: float = 0.0

    acquisition_budget_ok: bool = True


@dataclass(frozen=True)
class ActionRoutingResult:
    action: ManualAction
    reason_code: str
    protocol_feasible: bool
    static_feasible: bool


def select_action(
    signals: RoutingSignals,
    *,
    minimum_expected_utility: float = 0.0,
) -> ActionRoutingResult:
    """Choose an action using a fixed, auditable precedence order."""

    severe_conflict = (
        signals.explicit_conflict_count >= 2
        or signals.cross_vendor_conflict
        or signals.authenticity_doubt
    )
    protocol_feasible = (
        signals.acquisition_budget_ok
        and signals.protocol_endpoint_observed
        and signals.protocol_probe_returns_target
        and signals.protocol_expected_utility >= minimum_expected_utility
    )
    static_feasible = (
        signals.acquisition_budget_ok
        and signals.static_endpoint_observed
        and (signals.static_path_device_linked or signals.temporal_match_possible)
        and signals.static_expected_utility >= minimum_expected_utility
    )

    if (
        signals.exact_value_supported
        and signals.candidate_locatable
        and signals.attribute_role_valid
        and signals.source_authorized
        and not severe_conflict
    ):
        return ActionRoutingResult(
            ManualAction.ACCEPT,
            "EXACT_AUTHORIZED_SUPPORT",
            protocol_feasible,
            static_feasible,
        )

    if severe_conflict:
        return ActionRoutingResult(
            ManualAction.ESCALATE,
            "UNRESOLVED_IDENTITY_OR_AUTHENTICITY_CONFLICT",
            protocol_feasible,
            static_feasible,
        )

    if signals.coarse_value_supported and not signals.candidate_wrong_role:
        return ActionRoutingResult(
            ManualAction.REDUCE_GRANULARITY,
            "CURRENT_EVIDENCE_SUPPORTS_COARSER_VALUE",
            protocol_feasible,
            static_feasible,
        )

    if signals.candidate_wrong_role:
        return ActionRoutingResult(
            ManualAction.ABSTAIN,
            "CANDIDATE_HAS_WRONG_ATTRIBUTE_ROLE",
            protocol_feasible,
            static_feasible,
        )

    if protocol_feasible and static_feasible:
        if signals.static_expected_utility > signals.protocol_expected_utility:
            action = ManualAction.ACQUIRE_STATIC_INFO
            reason = "STATIC_PATH_HAS_HIGHER_EXPECTED_UTILITY"
        else:
            action = ManualAction.ACQUIRE_PROTOCOL_INFO
            reason = "PROTOCOL_PATH_HAS_HIGHER_OR_EQUAL_EXPECTED_UTILITY"
        return ActionRoutingResult(action, reason, True, True)

    if protocol_feasible:
        return ActionRoutingResult(
            ManualAction.ACQUIRE_PROTOCOL_INFO,
            "KNOWN_PROTOCOL_PROBE_CAN_RETURN_TARGET_FIELD",
            True,
            False,
        )

    if static_feasible:
        return ActionRoutingResult(
            ManualAction.ACQUIRE_STATIC_INFO,
            "DEVICE_LINKED_STATIC_OR_TEMPORAL_PATH_AVAILABLE",
            False,
            True,
        )

    return ActionRoutingResult(
        ManualAction.ABSTAIN,
        "NO_EXECUTABLE_EVIDENCE_PATH",
        protocol_feasible,
        static_feasible,
    )

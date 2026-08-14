"""Tool-independent actions exposed by the VeriClaim decision boundary."""

from __future__ import annotations

from enum import Enum


class PolicyAction(str, Enum):
    ACCEPT = "ACCEPT"
    REDUCE_GRANULARITY = "REDUCE_GRANULARITY"
    ACQUIRE = "ACQUIRE"
    ESCALATE = "ESCALATE"
    ABSTAIN = "ABSTAIN"


class ManualAction(str, Enum):
    """Concrete externally visible actions used by the reference router."""

    ACCEPT = "ACCEPT"
    REDUCE_GRANULARITY = "REDUCE_GRANULARITY"
    ACQUIRE_PROTOCOL_INFO = "ACQUIRE_PROTOCOL_INFO"
    ACQUIRE_STATIC_INFO = "ACQUIRE_STATIC_INFO"
    ACQUIRE_EXTERNAL_INFO = "ACQUIRE_EXTERNAL_INFO"
    ESCALATE = "ESCALATE"
    ABSTAIN = "ABSTAIN"

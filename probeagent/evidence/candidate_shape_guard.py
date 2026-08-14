"""Low-risk candidate-shape vetoes applied before learned verification.

Only final release rules belong here. The guard is deliberately small:
semantic role decisions remain the responsibility of the source-aware verifier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date


SHORT_BARE_FIRMWARE_INTEGER = re.compile(r"^\d{1,3}$")
SHORT_BARE_BRAND_INTEGER = re.compile(r"^\d{1,2}$")
SHORT_BARE_MODEL_INTEGER = re.compile(r"^\d{1,3}$")
DELIMITED_DATE = re.compile(
    r"^(?P<year>\d{4})[-/.](?P<month>\d{1,2})[-/.](?P<day>\d{1,2})"
    r"(?:[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$",
    re.IGNORECASE,
)
COMPACT_DATE = re.compile(r"^(?P<year>\d{4})(?P<month>\d{2})(?P<day>\d{2})$")
BARE_EPOCH = re.compile(r"^\d{10}(?:\d{3})?$")
GENERIC_BRAND_VALUES = frozenset(
    {
        "bacnet",
        "coap",
        "dhcp",
        "dnp3",
        "dns",
        "ethercat",
        "ethernetip",
        "fins",
        "ftp",
        "general",
        "generic",
        "http",
        "https",
        "ipmi",
        "ipp",
        "knx",
        "modbus",
        "mqtt",
        "onvif",
        "onvifipnc",
        "opcua",
        "private",
        "rtsp",
        "s7",
        "sip",
        "smtp",
        "snmp",
        "ssdp",
        "ssh",
        "telnet",
        "unknown",
        "upnp",
    }
)
@dataclass(frozen=True)
class CandidateShapeDecision:
    blocked: bool
    reason: str = ""
    recommended_action: str = ""


def _compact_alnum(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _valid_calendar_date(match: re.Match[str]) -> bool:
    try:
        date(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
        )
        return True
    except ValueError:
        return False


def _is_bare_date_or_timestamp(value: str) -> bool:
    delimited = DELIMITED_DATE.fullmatch(value)
    if delimited and _valid_calendar_date(delimited):
        return True
    compact = COMPACT_DATE.fullmatch(value)
    if compact and _valid_calendar_date(compact):
        return True
    if BARE_EPOCH.fullmatch(value):
        raw = int(value)
        seconds = raw // 1000 if len(value) == 13 else raw
        return 946_684_800 <= seconds <= 4_102_444_800
    return False


def evaluate_candidate_shape(
    attribute: object,
    value: object,
) -> CandidateShapeDecision:
    normalized_attribute = str(attribute or "").strip().lower()
    normalized_value = str(value or "").strip()
    if (
        normalized_attribute == "firmware_version"
        and SHORT_BARE_FIRMWARE_INTEGER.fullmatch(normalized_value)
    ):
        return CandidateShapeDecision(
            blocked=True,
            reason="firmware_bare_short_integer",
            recommended_action="ABSTAIN",
        )
    if (
        normalized_attribute == "brand"
        and SHORT_BARE_BRAND_INTEGER.fullmatch(normalized_value)
    ):
        return CandidateShapeDecision(
            blocked=True,
            reason="brand_bare_short_integer",
            recommended_action="ABSTAIN",
        )
    if (
        normalized_attribute == "model"
        and SHORT_BARE_MODEL_INTEGER.fullmatch(normalized_value)
    ):
        return CandidateShapeDecision(
            blocked=True,
            reason="model_bare_short_integer",
            recommended_action="ABSTAIN",
        )
    if (
        normalized_attribute == "firmware_version"
        and _is_bare_date_or_timestamp(normalized_value)
    ):
        return CandidateShapeDecision(
            blocked=True,
            reason="firmware_bare_date_or_timestamp",
            recommended_action="ABSTAIN",
        )
    if (
        normalized_attribute == "brand"
        and _compact_alnum(normalized_value) in GENERIC_BRAND_VALUES
    ):
        return CandidateShapeDecision(
            blocked=True,
            reason="brand_protocol_or_generic_identity",
            recommended_action="ABSTAIN",
        )
    if (
        normalized_attribute == "model"
        and normalized_value
        and len(_compact_alnum(normalized_value)) < 3
    ):
        return CandidateShapeDecision(
            blocked=True,
            reason="model_too_short",
            recommended_action="ABSTAIN",
        )
    return CandidateShapeDecision(blocked=False)

"""Identity alias and contradiction checks for brand/model claims.

The checks here are intentionally conservative. They are designed to catch
obvious cross-vendor identity conflicts without turning every unsupported brand
claim into a hard reject.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


def clean(value: Any) -> str:
    return " ".join(str(value or "").replace("\x00", "").strip().split())


def norm(value: Any) -> str:
    return clean(value).lower()


def brand_key(value: Any) -> str:
    text = norm(value)
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    words = [w for w in text.split() if w not in {"inc", "incorporated", "corp", "corporation", "co", "ltd", "limited"}]
    return " ".join(words)


BRAND_ALIASES: dict[str, set[str]] = {
    "apc": {"apc", "schneider", "schneider electric"},
    "axis": {"axis", "axis communications"},
    "checkpoint": {"checkpoint", "check point"},
    "check point": {"checkpoint", "check point"},
    "dahua": {"dahua", "dahua technology"},
    "grandstream": {"grandstream"},
    "hanwha": {"hanwha", "samsung", "samsung techwin"},
    "hp": {"hp", "hewlett packard", "hpe", "hewlett packard enterprise"},
    "hpe": {"hp", "hpe", "hewlett packard", "hewlett packard enterprise"},
    "mikrotik": {"mikrotik", "routeros"},
    "qnap": {"qnap", "qts"},
    "sonicwall": {"sonicwall", "sonic wall"},
    "synology": {"synology", "dsm", "diskstation", "rackstation"},
    "ubiquiti": {"ubiquiti", "unifi", "airmax"},
    "zyxel": {"zyxel", "zyxel communications"},
}

SERVICE_VENDOR_HINTS: dict[str, set[str]] = {
    "acti": {"acti"},
    "checkpoint": {"checkpoint", "check point"},
    "mikrotik": {"mikrotik", "routeros"},
    "synology": {"synology", "dsm"},
}

CONFLICT_CUES = (
    "conflicting identity",
    "different vendor/model",
    "different vendor",
    "different model",
    "identity conflict",
    "vendor conflict",
    "model conflict",
)


@dataclass(frozen=True)
class IdentityAliasDecision:
    hard_reject: bool
    route_action: str
    reasons: tuple[str, ...]
    candidate_supported: bool
    service_vendor_hint: str


def aliases_for(value: Any) -> set[str]:
    key = brand_key(value)
    aliases = {key} if key else set()
    aliases.update(BRAND_ALIASES.get(key, set()))
    return {brand_key(alias) for alias in aliases if brand_key(alias)}


def text_has_alias(text: str, aliases: set[str]) -> bool:
    haystack = f" {brand_key(text)} "
    for alias in aliases:
        if not alias:
            continue
        needle = f" {alias} "
        if needle in haystack:
            return True
    return False


def service_vendor_hint(service: Any) -> str:
    service_key = brand_key(service)
    if not service_key:
        return ""
    for hint, aliases in SERVICE_VENDOR_HINTS.items():
        if hint in service_key:
            return hint
        if any(alias and alias in service_key for alias in aliases):
            return hint
    return ""


def identity_conflict_cue(context: Any) -> bool:
    text = norm(context)
    return any(cue in text for cue in CONFLICT_CUES)


def identity_alias_route(row: dict[str, Any], *, context: Any = "") -> IdentityAliasDecision:
    """Return a conservative identity route decision.

    Hard rejects are limited to:
    - explicit observed contradiction cues in the evidence text; or
    - service-level vendor hints that conflict with a brand candidate.

    Lack of support alone is not a hard reject because many clean samples only
    have weak service or title evidence after snippet compression.
    """

    attr = norm(row.get("attribute"))
    candidate = row.get("candidate_value")
    aliases = aliases_for(candidate)
    service = row.get("service") or row.get("service_name")
    hint = service_vendor_hint(service)
    reasons: list[str] = []

    supported = bool(aliases and (text_has_alias(context, aliases) or text_has_alias(service, aliases)))

    if attr not in {"brand", "model"}:
        return IdentityAliasDecision(False, "PASS", tuple(), supported, hint)

    if identity_conflict_cue(context):
        reasons.append("identity_conflict_cue_in_observed_context")

    if attr == "brand" and hint:
        hint_aliases = aliases_for(hint)
        if aliases and aliases.isdisjoint(hint_aliases):
            reasons.append(f"service_vendor_mismatch:{hint}")

    if reasons:
        return IdentityAliasDecision(True, "ESCALATE_OR_REJECT", tuple(sorted(set(reasons))), supported, hint)

    if not supported:
        return IdentityAliasDecision(False, "SOFT_UNSUPPORTED_IDENTITY", ("identity_not_located_in_retained_context",), supported, hint)

    return IdentityAliasDecision(False, "PASS", tuple(), supported, hint)

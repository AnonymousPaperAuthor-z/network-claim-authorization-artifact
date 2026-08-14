"""Deployable identity-assertion extraction and contradiction detection.

The extractor only emits assertions that can be traced to inference-time text.
It handles explicit device identity fields and conservative vendor mentions in
device-facing titles.  It deliberately ignores generic server/component fields.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping

from probeagent.evidence.identity_alias import BRAND_ALIASES, brand_key


EXPLICIT_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "brand": (
        re.compile(
            r"\b(?:manufacturer|vendor|brand|make)\s*[:=]\s*"
            r"([^\r\n<>\[\]{}|;,]{2,96})",
            re.I,
        ),
    ),
    "model": (
        re.compile(
            r"\b(?:model|modelname|model_name|product|productname|product_name|device\s*type)"
            r"\s*[:=]\s*([^\r\n<>\[\]{}|;,]{2,128})",
            re.I,
        ),
    ),
    "firmware_version": (
        re.compile(
            r"\b(?:firmware(?:\s*version)?|firmwareversion|fwver|fw\s*version)"
            r"\s*[:=]\s*([Vv]?[A-Za-z0-9][A-Za-z0-9._+\-/]{0,64})",
            re.I,
        ),
    ),
}

NEXT_FIELD = re.compile(
    r"\s+(?=(?:manufacturerurl|manufacturer|vendor|brand|make|modeldescription|modelname|"
    r"model_name|model|productname|product_name|product|device\s*type|firmwareversion|"
    r"firmware\s*version|firmware|fwver|fw\s*version|serialnumber|http[_ ]?title|"
    r"screenshot[_ ]?title|page[_ ]?title|title)\s*[:=])",
    re.I,
)

MARKER = re.compile(r"(?m)^\s*\[([^\]\r\n]{1,80})\]\s*")
HTML_TITLE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.I | re.S)
LABELED_TITLE = re.compile(
    r"(?im)^\s*(?:http[_ ]?title|screenshot[_ ]?title|page[_ ]?title|title)\s*[:=]\s*([^\r\n]{2,240})"
)

# These aliases are intentionally limited to device vendors.  New aliases must
# be versioned or supplied from the audited identity KB at runtime.
DEFAULT_DEVICE_BRAND_ALIASES: dict[str, set[str]] = {
    **BRAND_ALIASES,
    "hikvision": {"hikvision", "hikvision digital technology"},
    "dahua": {"dahua", "dahua technology"},
    "dzs": {"dzs", "dasanzhone", "zhone"},
    "cisco": {"cisco", "cisco systems"},
    "d-link": {"d-link", "dlink"},
    "siemens": {"siemens", "siemens building technologies"},
    "zte": {"zte", "zte corporation"},
}

GENERIC_IDENTITY_VALUES = {
    "general",
    "generic",
    "generic vendor",
    "manufacturer",
    "private",
    "unknown",
}

HTML_ATTRIBUTE_TOKENS = {
    "activepassword",
    "autocomplete",
    "maxlength",
    "onpaste",
    "password",
    "placeholder",
    "username",
}


def clean(value: Any) -> str:
    return " ".join(str(value or "").replace("\x00", " ").split()).strip(" .,:;\"'")


def _field_value(value: Any) -> str:
    text = clean(value)
    text = NEXT_FIELD.split(text, maxsplit=1)[0]
    return clean(text)


def _invalid_identity_value(attribute: str, value: str) -> bool:
    normalized = brand_key(value)
    if not normalized or normalized in GENERIC_IDENTITY_VALUES:
        return True
    words = set(normalized.split())
    if attribute in {"brand", "model"} and words & HTML_ATTRIBUTE_TOKENS:
        return True
    if "http www" in normalized or normalized.startswith("http "):
        return True
    return False


def _source_type(marker: str) -> str:
    value = marker.lower().replace("-", "_").replace(" ", "_")
    if any(token in value for token in ("onvif", "snmp", "bacnet", "modbus", "fins", "sip", "ssdp", "upnp")):
        return "protocol_self_report"
    if "title" in value or "screenshot" in value:
        return "screenshot_title"
    if "static" in value or "resource" in value:
        return "static_resource"
    if "deep" in value:
        return "deep_probe_context"
    if "banner" in value:
        return "device_banner"
    return value or "untyped_evidence"


def split_segments(text: str) -> list[tuple[str, str, int]]:
    matches = list(MARKER.finditer(text or ""))
    if not matches:
        return [("untyped_evidence", text or "", 0)]
    segments: list[tuple[str, str, int]] = []
    if matches[0].start() > 0:
        segments.append(("untyped_evidence", text[: matches[0].start()], 0))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        segments.append((_source_type(match.group(1)), text[match.end() : end], match.end()))
    return segments


def _alias_index(
    additional_brands: Iterable[str] = (),
) -> tuple[dict[str, str], list[tuple[str, str]]]:
    alias_to_canonical: dict[str, str] = {}
    for canonical, aliases in DEFAULT_DEVICE_BRAND_ALIASES.items():
        canonical_key = brand_key(canonical)
        for alias in set(aliases) | {canonical}:
            alias_key = brand_key(alias)
            if alias_key:
                alias_to_canonical[alias_key] = canonical_key
    for brand in additional_brands:
        key = brand_key(brand)
        if key and key not in GENERIC_IDENTITY_VALUES:
            alias_to_canonical.setdefault(key, key)
    # Longest first avoids matching "hp" inside a longer explicit alias.
    ordered = sorted(alias_to_canonical.items(), key=lambda item: (-len(item[0]), item[0]))
    return alias_to_canonical, ordered


def _canonical_brand(value: str, alias_to_canonical: dict[str, str]) -> str:
    key = brand_key(value)
    return alias_to_canonical.get(key, key)


def _contains_alias(text: str, alias: str) -> bool:
    normalized = f" {brand_key(text)} "
    return bool(alias and f" {alias} " in normalized)


@dataclass(frozen=True)
class IdentityAssertion:
    attribute: str
    value: str
    normalized_value: str
    source: str
    field_role: str
    confidence: str
    span_start: int
    span_end: int
    span_text: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_identity_assertions(
    text: str,
    *,
    additional_brands: Iterable[str] = (),
) -> list[IdentityAssertion]:
    alias_to_canonical, ordered_aliases = _alias_index(additional_brands)
    assertions: list[IdentityAssertion] = []
    seen: set[tuple[str, str, str, int]] = set()

    for source, segment, offset in split_segments(text or ""):
        for attribute, patterns in EXPLICIT_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(segment):
                    value = _field_value(match.group(1))
                    if _invalid_identity_value(attribute, value):
                        continue
                    normalized = (
                        _canonical_brand(value, alias_to_canonical)
                        if attribute == "brand"
                        else brand_key(value)
                    )
                    key = (attribute, normalized, source, offset + match.start(1))
                    if not normalized or key in seen:
                        continue
                    seen.add(key)
                    assertions.append(
                        IdentityAssertion(
                            attribute=attribute,
                            value=value,
                            normalized_value=normalized,
                            source=source,
                            field_role=f"explicit_{attribute}_field",
                            confidence="high",
                            span_start=offset + match.start(1),
                            span_end=offset + match.end(1),
                            span_text=match.group(0),
                        )
                    )

        title_matches = list(HTML_TITLE.finditer(segment)) + list(LABELED_TITLE.finditer(segment))
        for title_match in title_matches:
            title = clean(title_match.group(1))
            for alias, canonical in ordered_aliases:
                if not _contains_alias(title, alias):
                    continue
                key = ("brand", canonical, source, offset + title_match.start(1))
                if key in seen:
                    continue
                seen.add(key)
                assertions.append(
                    IdentityAssertion(
                        attribute="brand",
                        value=title,
                        normalized_value=canonical,
                        source="screenshot_title" if source == "untyped_evidence" else source,
                        field_role="device_facing_title_brand_mention",
                        confidence="medium",
                        span_start=offset + title_match.start(1),
                        span_end=offset + title_match.end(1),
                        span_text=title_match.group(0),
                    )
                )
                break
    return assertions


def validate_semantic_assertions(
    text: str,
    rows: Iterable[Mapping[str, Any]],
    *,
    additional_brands: Iterable[str] = (),
) -> list[IdentityAssertion]:
    """Validate semantic-extractor output against literal inference-time spans.

    A model may propose the semantic role of a span, but it cannot invent the
    span, source, subject, or value.  Only device-subject assertions with an
    exact quote in the runtime evidence are admitted to the conflict graph.
    """

    alias_to_canonical, _ = _alias_index(additional_brands)
    assertions: list[IdentityAssertion] = []
    seen: set[tuple[str, str, str, int]] = set()
    for row in rows:
        attribute = clean(row.get("attribute")).lower()
        value = clean(row.get("value"))
        quote = str(row.get("span_quote") or "")
        subject = clean(row.get("subject")).lower()
        source = clean(row.get("source")) or "semantic_untyped"
        field_role = clean(row.get("field_role")) or "semantic_device_identity"
        if attribute not in EXPLICIT_PATTERNS or subject not in {"device", "target_device"}:
            continue
        if not value or not quote or _invalid_identity_value(attribute, value):
            continue
        start = text.find(quote)
        if start < 0:
            continue
        normalized = (
            _canonical_brand(value, alias_to_canonical)
            if attribute == "brand"
            else brand_key(value)
        )
        if not normalized:
            continue
        quote_norm = brand_key(quote)
        if attribute == "brand":
            aliases = {
                alias
                for alias, canonical in alias_to_canonical.items()
                if canonical == normalized
            } | {normalized}
            if not any(_contains_alias(quote, alias) for alias in aliases):
                continue
        elif normalized not in quote_norm:
            continue
        key = (attribute, normalized, source, start)
        if key in seen:
            continue
        seen.add(key)
        assertions.append(
            IdentityAssertion(
                attribute=attribute,
                value=value,
                normalized_value=normalized,
                source=source,
                field_role=field_role,
                confidence="semantic_span_validated",
                span_start=start,
                span_end=start + len(quote),
                span_text=quote,
            )
        )
    return assertions


def detect_identity_conflicts(
    text: str,
    *,
    additional_brands: Iterable[str] = (),
    semantic_assertions: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    assertions = extract_identity_assertions(text, additional_brands=additional_brands)
    assertions.extend(
        validate_semantic_assertions(
            text,
            semantic_assertions,
            additional_brands=additional_brands,
        )
    )
    deduplicated: list[IdentityAssertion] = []
    seen_assertions: set[tuple[str, str, str, int]] = set()
    for assertion in assertions:
        key = (
            assertion.attribute,
            assertion.normalized_value,
            assertion.source,
            assertion.span_start,
        )
        if key not in seen_assertions:
            deduplicated.append(assertion)
            seen_assertions.add(key)
    assertions = deduplicated
    by_attribute: dict[str, dict[str, list[IdentityAssertion]]] = {}
    for assertion in assertions:
        by_attribute.setdefault(assertion.attribute, {}).setdefault(
            assertion.normalized_value, []
        ).append(assertion)

    conflicts: list[dict[str, Any]] = []
    for attribute, values in by_attribute.items():
        if len(values) < 2:
            continue
        ordered_values = sorted(values)
        for left_index, left in enumerate(ordered_values):
            for right in ordered_values[left_index + 1 :]:
                left_assertions = values[left]
                right_assertions = values[right]
                left_sources = {item.source for item in left_assertions}
                right_sources = {item.source for item in right_assertions}
                if left_sources == right_sources == {"untyped_evidence"}:
                    continue
                conflicts.append(
                    {
                        "attribute": attribute,
                        "left_value": left,
                        "right_value": right,
                        "left_sources": sorted(left_sources),
                        "right_sources": sorted(right_sources),
                        "left_spans": [item.to_dict() for item in left_assertions],
                        "right_spans": [item.to_dict() for item in right_assertions],
                        "reason": "COMPETING_LOCATABLE_IDENTITY_ASSERTIONS",
                    }
                )

    return {
        "assertions": [item.to_dict() for item in assertions],
        "conflicts": conflicts,
        "conflict_count": len(conflicts),
        "conflicting_attributes": sorted({item["attribute"] for item in conflicts}),
    }

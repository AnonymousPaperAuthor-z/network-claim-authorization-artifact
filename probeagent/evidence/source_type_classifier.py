"""Source-type span classifier used by CSDA.

The classifier is a rule-based local detector for source provenance classes used
by Counterfactual Source-Dependency Attribution. It returns all matching labels
for a span instead of choosing one winner because CSDA masks source types
independently.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from probeagent.evidence.source_type_patterns import (
    CACHE_ARTIFACT_RE,
    COMPONENT_VERSION_RE,
    DEVICE_BANNER_RE,
    HTML_TITLE_RE,
    LIBRARY_VERSION_RE,
    PROTOCOL_SELF_REPORT_RE,
    SERVER_SOFTWARE_RE,
    SOURCE_TYPES,
    STATIC_RESOURCE_RE,
    VERSION_LIKE_RE,
)


NON_EVIDENCE_LINE_RE = re.compile(
    r"^(?:"
    r"Observed evidence for device identity extraction\.?|"
    r"Important instructions:?|"
    r"-\s*Extract vendor, model, firmware_version and components only from the observed evidence below\.?|"
    r"-\s*Preserve protocol/banner/static-resource context when deciding whether a version is firmware, component, or cache noise\.?|"
    r"-\s*Last-Modified dates alone are temporal evidence, not firmware versions\.?|"
    r"-\s*IP addresses are redacted as <IP>.*|"
    r"-\s*Web framework, PHP, Apache, nginx, OpenSSL, SSH, OS, or application component versions.*|"
    r"\[TARGET_METADATA\]|"
    r"record_id=\S+.*\b(?:ip_hash|source_line_no|port_index)=\S+.*"
    r")$",
    re.IGNORECASE,
)

SERIALIZER_HASH_FIELD_RE = re.compile(
    r"(?i)\b(?:sha256|text_sha256|ip_hash)\s*=\s*([a-f0-9]{16,})"
)

PASE_UNIT_HEADER_RE = re.compile(
    r"(?m)^\[PASE_UNIT\b[^\]\n]*\bsource=(?P<source>[a-z_]+)[^\]\n]*\][^\n]*$",
    re.IGNORECASE,
)

SERIALIZED_SECTION_HEADER_RE = re.compile(
    r"(?m)^\[(?P<marker>"
    r"TARGET_METADATA|RAW_BANNER_LIST|BANNER(?:_FULL)?(?:\s+\d+)?|"
    r"VERSION_AWARE_RAW_RETENTION|VERSION_RAW(?:\s+\d+)?|"
    r"DEEP_PROTOCOL_BANNER(?:_LIST)?|DEEP_PROTOCOL_VIRTUAL_BANNER|"
    r"DEEP_PRODUCT_BANNER_LIST|DEEP_PRODUCT_VIRTUAL_BANNER|"
    r"APP_DETECTION_SUMMARY_OBSERVED|SCREENSHOT_AND_PAGE|"
    r"STATIC_FULL(?:_TRUNCATED)?(?:\s+\d+)?|STATIC_RESOURCE_AGGREGATION"
    r")\][^\n]*$",
    re.IGNORECASE,
)

PASE_SOURCE_MAP = {
    "device_banner": "device_banner",
    "deep_product": "device_banner",
    "component_version": "component_version",
    "static_resource": "static_resource",
    "screenshot_title": "screenshot_title",
}

SECTION_SOURCE_MAP = {
    "banner": "device_banner",
    "banner_full": "device_banner",
    "deep_protocol_banner": "protocol_self_report",
    "deep_protocol_banner_list": "protocol_self_report",
    "deep_protocol_virtual_banner": "protocol_self_report",
    "deep_product_banner_list": "device_banner",
    "deep_product_virtual_banner": "device_banner",
    "app_detection_summary_observed": "component_version",
    "screenshot_and_page": "screenshot_title",
    "static_full": "static_resource",
    "static_full_truncated": "static_resource",
    "static_resource_aggregation": "static_resource",
}


@dataclass(frozen=True)
class SpanLabel:
    start: int
    end: int
    text: str
    source_type: str
    confidence: float
    rule_id: str
    subtype: str | None = None


def _line_bounds(context: str, start: int, end: int) -> tuple[int, int]:
    left = context.rfind("\n", 0, start) + 1
    right = context.find("\n", end)
    if right == -1:
        right = len(context)
    return left, right


def _trim_bounds(context: str, start: int, end: int) -> tuple[int, int]:
    while start < end and context[start].isspace():
        start += 1
    while end > start and context[end - 1].isspace():
        end -= 1
    return start, end


def _add_label(
    labels: list[SpanLabel],
    context: str,
    start: int,
    end: int,
    source_type: str,
    confidence: float,
    rule_id: str,
    subtype: str | None = None,
) -> None:
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"unknown source type: {source_type}")
    start, end = _trim_bounds(context, max(0, start), min(len(context), end))
    if end <= start:
        return
    labels.append(
        SpanLabel(
            start=start,
            end=end,
            text=context[start:end],
            source_type=source_type,
            confidence=confidence,
            rule_id=rule_id,
            subtype=subtype,
        )
    )


def _iter_lines(context: str) -> list[tuple[int, int, str]]:
    lines: list[tuple[int, int, str]] = []
    offset = 0
    for raw_line in context.splitlines(keepends=True):
        end = offset + len(raw_line)
        text = raw_line.rstrip("\r\n")
        lines.append((offset, offset + len(text), text))
        offset = end
    if context and not lines:
        lines.append((0, len(context), context))
    return lines


def _is_non_evidence_line(line: str) -> bool:
    """Return true for serializer instructions/metadata, not endpoint evidence."""
    return bool(NON_EVIDENCE_LINE_RE.match(line.strip()))


def _match_is_on_non_evidence_line(context: str, start: int, end: int) -> bool:
    """Prevent global regexes from reintroducing prompt scaffolding as evidence."""
    left, right = _line_bounds(context, start, end)
    return _is_non_evidence_line(context[left:right])


def _cache_match_is_serializer_hash(context: str, start: int, end: int) -> bool:
    """Exclude transport/wrapper hashes while retaining endpoint cache tokens."""
    left, right = _line_bounds(context, start, end)
    line = context[left:right]
    relative_start = start - left
    relative_end = end - left
    for match in SERIALIZER_HASH_FIELD_RE.finditer(line):
        value_start, value_end = match.span(1)
        if relative_start >= value_start and relative_end <= value_end:
            return True
    return False


def _metadata_values(mapping: dict[str, Any] | None) -> list[str]:
    if not mapping:
        return []
    values: list[str] = []
    for key, value in mapping.items():
        key_text = str(key or "").lower().split(".")[-1]
        if key_text in {
            "service",
            "service_name",
            "service_version",
            "protocol",
            "trans_protocol",
            "port",
            "audit_field_span_source",
            "support_sources",
        }:
            continue
        if isinstance(value, str):
            values.append(f"{key}: {value}")
        elif isinstance(value, (list, tuple)):
            values.extend(f"{key}: {item}" for item in value if item is not None)
        elif value is not None:
            values.append(f"{key}: {value}")
    return values


def _find_metadata_value_spans(context: str, values: list[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for value in values:
        value_text = str(value or "").strip()
        if not value_text:
            continue
        for term in {value_text, value_text.split(": ", 1)[-1]}:
            term = term.strip()
            if len(term) < 3:
                continue
            match = re.search(re.escape(term), context, flags=re.IGNORECASE)
            if match:
                spans.append(match.span())
                break
    return spans


def _after_line(context: str, position: int) -> int:
    """Return the first character after the line containing ``position``."""
    newline = context.find("\n", position)
    return len(context) if newline == -1 else newline + 1


def _normalize_section_marker(marker: str) -> str:
    return re.sub(r"\s+\d+$", "", marker.strip().lower())


def _add_serialized_block_labels(labels: list[SpanLabel], context: str) -> None:
    """Recover source provenance carried by lossless serializer block markers.

    PASE preserves exact source spans and emits an explicit ``source=`` field.
    Full serialization preserves equivalent section markers. The previous
    classifier ignored markers appearing after prompt instructions, so valid
    SNMP/Modbus/device-banner evidence could have zero source spans. Label only
    the observed block body: wrapper IDs and hashes stay outside the mask.
    """
    pase_headers = list(PASE_UNIT_HEADER_RE.finditer(context))
    if pase_headers:
        for index, header in enumerate(pase_headers):
            source = PASE_SOURCE_MAP.get(header.group("source").lower())
            if not source:
                continue
            block_end = pase_headers[index + 1].start() if index + 1 < len(pase_headers) else len(context)
            body_start = _after_line(context, header.end())
            nested = SERIALIZED_SECTION_HEADER_RE.match(context, body_start, block_end)
            if nested:
                body_start = _after_line(context, nested.end())
            _add_label(
                labels,
                context,
                body_start,
                block_end,
                source,
                0.97,
                f"serialized_block:pase_{header.group('source').lower()}",
            )
        return

    section_headers = list(SERIALIZED_SECTION_HEADER_RE.finditer(context))
    for index, header in enumerate(section_headers):
        marker = _normalize_section_marker(header.group("marker"))
        source = SECTION_SOURCE_MAP.get(marker)
        if not source:
            continue
        block_end = section_headers[index + 1].start() if index + 1 < len(section_headers) else len(context)
        body_start = _after_line(context, header.end())
        _add_label(
            labels,
            context,
            body_start,
            block_end,
            source,
            0.95,
            f"serialized_block:{marker}",
            subtype=(
                infer_protocol_subtype(text=context[body_start:block_end])
                if source == "protocol_self_report"
                else None
            ),
        )


def infer_protocol_subtype(
    *,
    service: str | None = None,
    text: str | None = None,
    protocol_fields: dict | None = None,
) -> str:
    blob_parts = [service or "", text or "", " ".join(_metadata_values(protocol_fields))]
    blob = " ".join(blob_parts).lower()
    if "onvif" in blob or "deviceinformation" in blob or "getdeviceinformation" in blob:
        return "onvif"
    if "snmp" in blob or "sysdescr" in blob or "sysname" in blob:
        return "snmp"
    if "bacnet" in blob or "firmwarerevision" in blob or "applicationsoftwarerevision" in blob:
        return "bacnet"
    if "ethernet/ip" in blob or "ethernetip" in blob or "identity object" in blob:
        return "ethernetip"
    if "fins" in blob or "controller data read" in blob:
        return "fins"
    if "modbus" in blob or "device identification" in blob:
        return "modbus"
    if "sip-tls" in blob or "siptls" in blob or "sip/tls" in blob or "sip/" in blob:
        return "sip_tls"
    return "other_protocol"


def classify_spans(
    context: str,
    protocol_fields: dict | None = None,
    http_sections: dict | None = None,
    service: str | None = None,
) -> list[SpanLabel]:
    """
    Returns source-type labels found in a raw observation context.

    The returned labels may overlap. Offsets are character positions in the
    provided context string.
    """
    context = str(context or "")
    labels: list[SpanLabel] = []
    if not context.strip():
        return labels

    _add_serialized_block_labels(labels, context)

    lines = _iter_lines(context)
    protocol_metadata = " ".join(_metadata_values(protocol_fields)).lower()
    http_metadata = " ".join(_metadata_values(http_sections)).lower()

    for line_no, (start, end, line) in enumerate(lines):
        stripped = line.strip()
        if not stripped or _is_non_evidence_line(stripped):
            continue
        if line_no == 0 and DEVICE_BANNER_RE.search(stripped):
            _add_label(labels, context, start, end, "device_banner", 0.78, "device_banner:first_line")
        elif line_no <= 3 and DEVICE_BANNER_RE.search(stripped) and not stripped.lower().startswith(("server:", "x-powered-by:")):
            _add_label(labels, context, start, end, "device_banner", 0.70, "device_banner:early_greeting")
        if PROTOCOL_SELF_REPORT_RE.search(stripped):
            subtype = infer_protocol_subtype(service=service, text=stripped, protocol_fields=protocol_fields)
            _add_label(
                labels,
                context,
                start,
                end,
                "protocol_self_report",
                0.90,
                "protocol_self_report:keyword_line",
                subtype=subtype,
            )

    if protocol_metadata:
        for start, end in _find_metadata_value_spans(context, _metadata_values(protocol_fields)):
            left, right = _line_bounds(context, start, end)
            subtype = infer_protocol_subtype(
                service=service,
                text=context[left:right],
                protocol_fields=protocol_fields,
            )
            _add_label(
                labels,
                context,
                left,
                right,
                "protocol_self_report",
                0.92,
                "protocol_self_report:metadata",
                subtype=subtype,
            )

    for match in SERVER_SOFTWARE_RE.finditer(context):
        if _match_is_on_non_evidence_line(context, match.start(), match.end()):
            continue
        _add_label(labels, context, match.start(), match.end(), "server_software", 0.95, "server_software:http_header")
    if http_metadata:
        for start, end in _find_metadata_value_spans(context, _metadata_values(http_sections)):
            left, right = _line_bounds(context, start, end)
            _add_label(labels, context, left, right, "server_software", 0.88, "server_software:metadata")

    for match in COMPONENT_VERSION_RE.finditer(context):
        if _match_is_on_non_evidence_line(context, match.start(), match.end()):
            continue
        _add_label(labels, context, match.start(), match.end(), "component_version", 0.88, "component_version:name_version")

    for match in LIBRARY_VERSION_RE.finditer(context):
        if _match_is_on_non_evidence_line(context, match.start(), match.end()):
            continue
        _add_label(labels, context, match.start(), match.end(), "library_version", 0.92, "library_version:name_version")

    for match in STATIC_RESOURCE_RE.finditer(context):
        start, end = match.span(1)
        if _match_is_on_non_evidence_line(context, start, end):
            continue
        _add_label(labels, context, start, end, "static_resource", 0.85, "static_resource:path_version")

    for match in CACHE_ARTIFACT_RE.finditer(context):
        if _match_is_on_non_evidence_line(context, match.start(), match.end()):
            continue
        if _cache_match_is_serializer_hash(context, match.start(), match.end()):
            continue
        _add_label(labels, context, match.start(), match.end(), "cache_artifact", 0.82, "cache_artifact:token")

    for match in HTML_TITLE_RE.finditer(context):
        if _match_is_on_non_evidence_line(context, match.start(), match.end()):
            continue
        text = match.group(0)
        confidence = 0.86 if VERSION_LIKE_RE.search(text) else 0.76
        _add_label(labels, context, match.start(), match.end(), "screenshot_title", confidence, "screenshot_title:title")

    deduplicated: dict[tuple[int, int, str], SpanLabel] = {}
    for label in labels:
        label_key = (label.start, label.end, label.source_type)
        existing = deduplicated.get(label_key)
        if existing is None or label.confidence > existing.confidence:
            deduplicated[label_key] = label
    result = list(deduplicated.values())
    result.sort(key=lambda item: (item.start, item.end, item.source_type, item.rule_id))
    return result

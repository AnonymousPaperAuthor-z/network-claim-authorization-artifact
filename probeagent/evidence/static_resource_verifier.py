"""Candidate-aware verifier for firmware versions in static resources.

Static resources are not uniformly trustworthy. A frontend library path such as
``jquery-1.7.2.min.js`` should not attest device firmware, while the same
firmware build string repeated across many device-owned UI assets can be useful
evidence. This module separates those cases without changing the raw CSA source
taxonomy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from typing import Any, Iterable, Mapping


MISSING_VALUES = {"", "none", "null", "unknown", "n/a", "na", "nil", "-"}

LIBRARY_KEYWORDS = {
    "jquery",
    "jquery-ui",
    "prototype",
    "modernizr",
    "requirejs",
    "require.js",
    "openlayers",
    "bootstrap",
    "react",
    "vue",
    "angular",
    "lodash",
    "underscore",
    "moment",
    "leaflet",
    "dojo",
    "extjs",
    "ext-all",
    "fontawesome",
    "datatables",
    "chart.js",
    "codemirror",
    "ckeditor",
    "tinymce",
    "d3.v",
    "headjs",
    "perfect-scrollbar",
}

CACHE_QUERY_KEYS = {
    "_dc",
    "_",
    "v",
    "ver",
    "version",
    "t",
    "ts",
    "time",
    "cache",
    "cachebuster",
    "r",
    "rev",
    "revision",
}

FIRMWARE_PATH_HINTS = {
    "firmware",
    "fw",
    "f/w",
    "upgrade",
    "update",
    "release",
    "build",
    "image",
    "rom",
    "bin",
    "pkg",
    "trx",
    "swu",
    "software",
    "system",
    "bundle",
    "package",
}

FIRMWARE_FILE_EXTENSIONS = {
    ".bin",
    ".img",
    ".rom",
    ".trx",
    ".pkg",
    ".swu",
    ".raucb",
    ".ipk",
    ".deb",
    ".rpm",
    ".tar",
    ".tgz",
    ".gz",
    ".zip",
}

STATIC_URL_RE = re.compile(
    r"(?P<url>/[A-Za-z0-9_./~:@%+?=&;,#-]{3,}|[A-Za-z0-9_.-]+\.(?:js|css|map|html?|json|bin|img|rom|trx|pkg|swu|zip|tar|tgz|gz)(?:\?[A-Za-z0-9_./~:@%+?=&;,#-]+)?)"
)

VERSION_PREFIX_RE = re.compile(
    r"^\s*(?:firmware|fw|f/w|software|sw|version|ver|release|build)\s*[:=_-]*\s*",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class StaticResourceFirmwareDecision:
    candidate_value: str
    support_level: str
    semantic_class: str
    direct_accept_candidate: bool
    temporal_hint_only: bool
    reject_static_artifact: bool
    reason: str
    hit_count: int
    distinct_hit_count: int
    non_library_hit_count: int
    library_hit_count: int
    query_hit_count: int
    path_hit_count: int
    firmware_hint_hit_count: int
    repeated_query_firmware_token: bool
    candidate_matches_known_firmware: bool
    sample_hits: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["sample_hits"] = list(self.sample_hits)
        return out


def clean(value: Any, default: str = "") -> str:
    text = " ".join(str(value or "").replace("\x00", "").strip().split())
    return text if text else default


def norm(value: Any, default: str = "") -> str:
    text = clean(value, default=default).lower()
    return text if text else default


def canonical_version(value: Any) -> str:
    text = clean(value)
    text = text.strip("\"'`[](){}<>")
    text = VERSION_PREFIX_RE.sub("", text).strip()
    return text


def compact_version(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", canonical_version(value).lower())


def candidate_value(row: Mapping[str, Any]) -> str:
    for key in (
        "candidate_value",
        "qwen_firmware",
        "audit_gold_firmware_start",
        "weak_firmware_start",
        "weak_firmware_end",
        "audit_gold_firmware_end",
    ):
        value = clean(row.get(key))
        if value and value.lower() not in MISSING_VALUES:
            return value
    normalized = row.get("normalized_candidate")
    if isinstance(normalized, Mapping):
        for key in ("firmware_version", "firmware", "version"):
            value = clean(normalized.get(key))
            if value and value.lower() not in MISSING_VALUES:
                return value
    return ""


def known_firmware_values(row: Mapping[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in (
        "qwen_firmware",
        "weak_firmware_start",
        "weak_firmware_end",
        "audit_gold_firmware_start",
        "audit_gold_firmware_end",
        "candidate_value",
    ):
        value = compact_version(row.get(key))
        if value and value not in MISSING_VALUES:
            values.add(value)
    normalized = row.get("normalized_candidate")
    if isinstance(normalized, Mapping):
        for key in ("firmware_version", "firmware", "version"):
            value = compact_version(normalized.get(key))
            if value:
                values.add(value)
    return values


def _parse_json_like_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if not isinstance(value, str):
        return []
    text = value.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def _source_span_texts(row: Mapping[str, Any]) -> Iterable[str]:
    summary = row.get("source_span_summary")
    if not isinstance(summary, Mapping):
        return
    for source in ("static_resource", "cache_artifact", "library_version"):
        item = summary.get(source)
        if not isinstance(item, Mapping):
            continue
        texts = item.get("sample_texts")
        if isinstance(texts, list):
            for text in texts:
                if clean(text):
                    yield clean(text)


def _static_section_lines(value: Any) -> list[str]:
    text = str(value or "")
    if not text.strip():
        return []
    out: list[str] = []
    in_static_section = False
    for raw_line in text.splitlines():
        line = clean(raw_line)
        if not line:
            continue
        upper = line.upper()
        if "STATIC_RESOURCE" in upper:
            in_static_section = True
            out.append(line)
            continue
        if upper.endswith("_SUMMARY:") or upper in {"CERTIFICATE_SUMMARY:", "ICON_SUMMARY:"}:
            in_static_section = False
        if in_static_section and ("[STATIC" in upper or "URL=" in upper or "LMT=" in upper or "REQ_NAME=" in upper):
            out.append(line)
    return out


def static_texts(row: Mapping[str, Any]) -> list[str]:
    texts: list[str] = []
    for key in ("static_urls_sample", "static_lmt_list"):
        for item in _parse_json_like_list(row.get(key)):
            if isinstance(item, Mapping):
                blob = " ".join(clean(item.get(k)) for k in ("url", "req_name", "lmt", "header", "header_sample"))
                if clean(blob):
                    texts.append(clean(blob))
            elif clean(item):
                texts.append(clean(item))
    for key in ("static_resource_prompt_context", "prompt_context_excerpt", "prompt_context"):
        texts.extend(_static_section_lines(row.get(key)))
    texts.extend(_source_span_texts(row))

    deduped: list[str] = []
    seen: set[str] = set()
    for text in texts:
        if not text:
            continue
        key = text[:500]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in STATIC_URL_RE.finditer(text):
        url = match.group("url").strip(".,;\"'()[]{}<>")
        if len(url) >= 3:
            urls.append(url)
    return urls


def _line_windows(text: str, candidate: str) -> list[str]:
    windows: list[str] = []
    cand_compact = compact_version(candidate)
    if not cand_compact:
        return windows
    for raw_line in str(text or "").splitlines():
        line = clean(raw_line)
        if not line:
            continue
        if cand_compact in compact_version(line):
            windows.append(line[:600])
    return windows


def _has_library_keyword(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in LIBRARY_KEYWORDS)


def _has_firmware_hint(text: str) -> bool:
    lowered = text.lower()
    path_part = lowered.split("?", 1)[0]
    tokens = {token for token in re.split(r"[^a-z0-9]+", path_part) if token}
    return bool(
        tokens & FIRMWARE_PATH_HINTS
        or any(path_part.endswith(ext) for ext in FIRMWARE_FILE_EXTENSIONS)
    )


def _candidate_hit(text: str, candidate: str) -> bool:
    raw = canonical_version(candidate).lower()
    compact = compact_version(candidate)
    lowered = text.lower()
    if raw and raw in lowered:
        return True
    return bool(compact and len(compact) >= 4 and compact in compact_version(text))


def _query_hit(text: str, candidate: str) -> bool:
    if "?" not in text:
        return False
    candidate_compact = compact_version(candidate)
    query = text.split("?", 1)[1]
    for part in re.split(r"[&#;]", query):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key.lower() in CACHE_QUERY_KEYS and candidate_compact and candidate_compact in compact_version(value):
            return True
    return False


def evaluate_static_resource_firmware(
    row: Mapping[str, Any],
    *,
    candidate: str | None = None,
) -> StaticResourceFirmwareDecision:
    cand = clean(candidate if candidate is not None else candidate_value(row))
    if not cand or cand.lower() in MISSING_VALUES:
        return StaticResourceFirmwareDecision(
            candidate_value=cand,
            support_level="none",
            semantic_class="empty_candidate",
            direct_accept_candidate=False,
            temporal_hint_only=False,
            reject_static_artifact=False,
            reason="No firmware candidate is available.",
            hit_count=0,
            distinct_hit_count=0,
            non_library_hit_count=0,
            library_hit_count=0,
            query_hit_count=0,
            path_hit_count=0,
            firmware_hint_hit_count=0,
            repeated_query_firmware_token=False,
            candidate_matches_known_firmware=False,
            sample_hits=(),
        )

    texts = static_texts(row)
    hits: list[str] = []
    for text in texts:
        urls = _extract_urls(text)
        candidates = urls if urls else _line_windows(text, cand)
        for item in candidates:
            if _candidate_hit(item, cand):
                hits.append(clean(item, default=item)[:500])

    distinct_hits = []
    seen = set()
    for hit in hits:
        key = hit.lower()
        if key not in seen:
            seen.add(key)
            distinct_hits.append(hit)

    library_hits = [hit for hit in distinct_hits if _has_library_keyword(hit)]
    non_library_hits = [hit for hit in distinct_hits if not _has_library_keyword(hit)]
    query_hits = [hit for hit in distinct_hits if _query_hit(hit, cand)]
    path_hits = [hit for hit in distinct_hits if hit not in query_hits]
    firmware_hint_hits = [hit for hit in distinct_hits if _has_firmware_hint(hit)]
    cand_compact = compact_version(cand)
    known_match = bool(cand_compact and cand_compact in known_firmware_values(row))
    repeated = len(distinct_hits) >= 2
    repeated_query = len(query_hits) >= 3 and known_match

    if not distinct_hits:
        has_static = any(clean(text) for text in texts)
        semantic = "static_context_without_candidate" if has_static else "no_static_context"
        return StaticResourceFirmwareDecision(
            candidate_value=cand,
            support_level="none",
            semantic_class=semantic,
            direct_accept_candidate=False,
            temporal_hint_only=has_static,
            reject_static_artifact=False,
            reason="Static context exists but the candidate firmware string was not found." if has_static else "No static resource context is available.",
            hit_count=0,
            distinct_hit_count=0,
            non_library_hit_count=0,
            library_hit_count=0,
            query_hit_count=0,
            path_hit_count=0,
            firmware_hint_hit_count=0,
            repeated_query_firmware_token=False,
            candidate_matches_known_firmware=known_match,
            sample_hits=(),
        )

    if library_hits and not non_library_hits:
        return StaticResourceFirmwareDecision(
            candidate_value=cand,
            support_level="negative",
            semantic_class="library_version_artifact",
            direct_accept_candidate=False,
            temporal_hint_only=False,
            reject_static_artifact=True,
            reason="Candidate appears only in known frontend/library asset paths.",
            hit_count=len(hits),
            distinct_hit_count=len(distinct_hits),
            non_library_hit_count=0,
            library_hit_count=len(library_hits),
            query_hit_count=len(query_hits),
            path_hit_count=len(path_hits),
            firmware_hint_hit_count=len(firmware_hint_hits),
            repeated_query_firmware_token=False,
            candidate_matches_known_firmware=known_match,
            sample_hits=tuple(distinct_hits[:5]),
        )

    if firmware_hint_hits:
        return StaticResourceFirmwareDecision(
            candidate_value=cand,
            support_level="strong",
            semantic_class="firmware_static_resource",
            direct_accept_candidate=True,
            temporal_hint_only=False,
            reject_static_artifact=False,
            reason="Candidate appears in static paths with firmware/update/build/package semantics.",
            hit_count=len(hits),
            distinct_hit_count=len(distinct_hits),
            non_library_hit_count=len(non_library_hits),
            library_hit_count=len(library_hits),
            query_hit_count=len(query_hits),
            path_hit_count=len(path_hits),
            firmware_hint_hit_count=len(firmware_hint_hits),
            repeated_query_firmware_token=repeated_query,
            candidate_matches_known_firmware=known_match,
            sample_hits=tuple(distinct_hits[:5]),
        )

    if known_match and len(path_hits) >= 3 and len(non_library_hits) >= 2:
        return StaticResourceFirmwareDecision(
            candidate_value=cand,
            support_level="strong",
            semantic_class="repeated_static_path_known_firmware_token",
            direct_accept_candidate=True,
            temporal_hint_only=False,
            reject_static_artifact=False,
            reason="Candidate matches a known firmware value and appears in repeated static resource path prefixes.",
            hit_count=len(hits),
            distinct_hit_count=len(distinct_hits),
            non_library_hit_count=len(non_library_hits),
            library_hit_count=len(library_hits),
            query_hit_count=len(query_hits),
            path_hit_count=len(path_hits),
            firmware_hint_hit_count=len(firmware_hint_hits),
            repeated_query_firmware_token=repeated_query,
            candidate_matches_known_firmware=known_match,
            sample_hits=tuple(distinct_hits[:5]),
        )

    if repeated_query:
        return StaticResourceFirmwareDecision(
            candidate_value=cand,
            support_level="strong",
            semantic_class="repeated_static_query_firmware_token",
            direct_accept_candidate=True,
            temporal_hint_only=False,
            reject_static_artifact=False,
            reason="Candidate matches a known firmware value and repeats as a version token across multiple static resources.",
            hit_count=len(hits),
            distinct_hit_count=len(distinct_hits),
            non_library_hit_count=len(non_library_hits),
            library_hit_count=len(library_hits),
            query_hit_count=len(query_hits),
            path_hit_count=len(path_hits),
            firmware_hint_hit_count=len(firmware_hint_hits),
            repeated_query_firmware_token=True,
            candidate_matches_known_firmware=known_match,
            sample_hits=tuple(distinct_hits[:5]),
        )

    if repeated and non_library_hits:
        return StaticResourceFirmwareDecision(
            candidate_value=cand,
            support_level="weak",
            semantic_class="repeated_static_version_token",
            direct_accept_candidate=False,
            temporal_hint_only=True,
            reject_static_artifact=False,
            reason="Candidate repeats across static resources, but lacks firmware semantics or known-firmware agreement.",
            hit_count=len(hits),
            distinct_hit_count=len(distinct_hits),
            non_library_hit_count=len(non_library_hits),
            library_hit_count=len(library_hits),
            query_hit_count=len(query_hits),
            path_hit_count=len(path_hits),
            firmware_hint_hit_count=len(firmware_hint_hits),
            repeated_query_firmware_token=False,
            candidate_matches_known_firmware=known_match,
            sample_hits=tuple(distinct_hits[:5]),
        )

    return StaticResourceFirmwareDecision(
        candidate_value=cand,
        support_level="weak" if non_library_hits else "negative",
        semantic_class="single_static_version_token" if non_library_hits else "static_artifact",
        direct_accept_candidate=False,
        temporal_hint_only=bool(non_library_hits),
        reject_static_artifact=not bool(non_library_hits),
        reason="Candidate appears in static resources but not enough to directly attest firmware.",
        hit_count=len(hits),
        distinct_hit_count=len(distinct_hits),
        non_library_hit_count=len(non_library_hits),
        library_hit_count=len(library_hits),
        query_hit_count=len(query_hits),
        path_hit_count=len(path_hits),
        firmware_hint_hit_count=len(firmware_hint_hits),
        repeated_query_firmware_token=False,
        candidate_matches_known_firmware=known_match,
        sample_hits=tuple(distinct_hits[:5]),
    )


def static_resource_firmware_features(row: Mapping[str, Any]) -> dict[str, Any]:
    decision = evaluate_static_resource_firmware(row)
    return {
        "firmware_static_resource_support": decision.support_level,
        "static_resource_semantic_class": decision.semantic_class,
        "firmware_static_resource_authorized": bool(decision.direct_accept_candidate),
        "firmware_static_resource_temporal_hint": bool(decision.temporal_hint_only),
        "firmware_static_resource_reject": bool(decision.reject_static_artifact),
        "firmware_static_resource_hit_count": int(decision.hit_count),
        "firmware_static_resource_distinct_hits": int(decision.distinct_hit_count),
        "firmware_static_resource_non_library_hits": int(decision.non_library_hit_count),
        "firmware_static_resource_library_hits": int(decision.library_hit_count),
        "firmware_static_resource_query_hits": int(decision.query_hit_count),
        "firmware_static_resource_path_hits": int(decision.path_hit_count),
        "firmware_static_resource_hint_hits": int(decision.firmware_hint_hit_count),
        "firmware_static_resource_known_firmware_match": bool(decision.candidate_matches_known_firmware),
        "firmware_static_resource_reason": decision.reason,
        "firmware_static_resource_sample_hits": " || ".join(decision.sample_hits),
    }

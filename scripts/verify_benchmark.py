#!/usr/bin/env python3
"""Verify the released VeriClaim-Sec corpus, gold, and privacy contract."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARK = ROOT / "benchmark/vericlaim_sec"
ATTRIBUTES = ("brand", "model", "firmware_version")
EXPECTED = {
    "candidate_verification": {
        "records": 2_000,
        "cells": 6_000,
        "positive": {"brand": 1_477, "model": 1_334, "firmware_version": 681},
    },
    "broad_record_complete": {
        "records": 6_000,
        "cells": 18_000,
        "positive": {"brand": 895, "model": 911, "firmware_version": 279},
    },
    "evidence_rich": {
        "records": 600,
        "cells": 1_800,
        "positive": {"brand": 520, "model": 467, "firmware_version": 376},
    },
}
ALLOWED_RECORD_FIELDS = {
    "schema_version",
    "record_id",
    "track",
    "service",
    "transport",
    "evidence",
    "evidence_sha256",
}
ALLOWED_CELL_FIELDS = {
    "schema_version",
    "cell_id",
    "record_id",
    "track",
    "attribute",
    "gold_values",
    "gold_supported",
}
INTERNAL_RECORD_RE = re.compile(r"\bdscan\d{8}:[^\s\]}>,]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")
IPV6_TOKEN_RE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{3,}(?![0-9A-Fa-f:])")
MAC_RE = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"
)
EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"
)
FQDN_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_.-])"
)
FILE_LIKE_SUFFIXES = (
    ".bin", ".css", ".gz", ".html", ".img", ".js", ".json", ".rom",
    ".tar", ".tgz", ".txt", ".xml", ".zip",
)
PUBLIC_HOST_SUFFIXES = {
    "ai", "au", "biz", "br", "ca", "cc", "ch", "cloud", "cn", "co",
    "com", "cz", "de", "edu", "es", "fr", "gov", "host", "hu", "in",
    "info", "int", "io", "it", "jp", "local", "me", "mil", "net", "nl",
    "org", "pl", "ru", "se", "systems", "uk", "us",
}
UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
)
URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"'),]+")
SERVICE_PORT_RE = re.compile(r"(?i)\b(?:tcp|udp)/\d+\b")
REDACTED_HOST_PORT_RE = re.compile(r"(?i)<(?:IP|HOST)>:\d+")
PORT_METADATA_RE = re.compile(
    r"(?i)\b(?:port_index|endpoint_port|source_port_index)\s*=\s*\d+\b"
)
PORT_FIELD_RE = re.compile(
    r"(?i)\b(?:sin\s+port|tcp\s+port|udp\s+port|src\s+port|dst\s+port|"
    r"source\s+port|destination\s+port|server\s+port|listening\s+port|"
    r"listen\s+port|endpoint\s+port|port)\s*[:=]\s*\d{1,5}\b"
)
SUFFIX_PORT_FIELD_RE = re.compile(
    r"(?i)\b(?P<field>[A-Za-z][A-Za-z0-9_-]*port|port)\s*[:=]\s*"
    r"[\"']?\d{1,5}[\"']?"
)
JSON_PORT_FIELD_RE = re.compile(
    r"(?i)[\"'](?:port|port_index|endpoint_port|source_port|destination_port)"
    r"[\"']\s*:\s*[\"']?\d{1,5}[\"']?"
)
SERIAL_VALUE_RE = re.compile(
    r"(?i)\b(?:serial(?:[ _-]*(?:number|no))?|uuid|udn|usn)\s*[:=]\s*"
    r"(?!<(?:SERIAL|UUID)>)[^\s<>,;]+"
)
PLAIN_IDENTIFIER_RE = re.compile(
    r"(?i)\b(?:device_serial|deviceid|serial(?:number|no|_number)?|uuid|udn|usn)"
    r"\s*[:=]\s*(?:uuid:)?(?:s:)?"
    r"(?!(?:<(?:SERIAL|UUID|REDACTED)>))[^\s<,;\"']{4,}"
)
JSON_IDENTIFIER_RE = re.compile(
    r"(?i)[\"'](?P<field>serial(?:number|no)?|deviceid|uuid|udn|usn)[\"']"
    r"\s*:\s*[\"'](?P<value>(?!<(?:SERIAL|UUID|REDACTED)>)[^\"']+)[\"']"
)
XML_IDENTIFIER_RE = re.compile(
    r"(?is)<(?!UUID\s*>|SERIAL\s*>|REDACTED\s*>|HOST\s*>)"
    r"(?:[A-Za-z_][\w.-]*:)?(?:SerialNumber|SerialNo|UUID|UDN|USN)"
    r"\b[^>]*>(?!<(?:SERIAL|UUID|REDACTED|HOST)>)[^<\r\n]{1,256}"
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^[ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key)[ \t]*:(?![ \t]*<REDACTED>[ \t]*\r?$)[^\r\n]+$"
)
COOKIE_CONTINUATION_RE = re.compile(
    r"(?im)^\s*[A-Za-z0-9_%+./=-]{8,512}\s*;\s*"
    r"(?=[^\r\n]*(?:expires|max-age|domain|path|samesite)\s*=)"
    r"[^\r\n]*(?:expires|max-age|domain|path|samesite)\s*=[^\r\n]*$"
)
PUBLIC_ACCOUNT_RE = re.compile(r"(?i)\bca-pub-\d{8,}\b")
RAW_TIMESTAMP_RE = re.compile(
    r"(?i)\btimestamp\s*[:=]\s*(?!<TIME>)(?:\d{4}-\d{2}-\d{2}|\S+)"
)
HTTP_TEMPORAL_HEADER_RE = re.compile(
    r"(?im)^\s*(?:date|last-modified|expires)\s*:\s*(?P<value>[^\r\n]+)$"
)
REQUEST_QUERY_RE = re.compile(r"(?i)\breq_path\s*=\s*[^\s\r\n]*[?#]")
CERT_FINGERPRINT_RE = re.compile(
    r"(?i)\b(?:fingerprint(?:_sha256)?|certificate_fingerprint|"
    r"cert_fingerprint|certificate_serial)\s*[:=]\s*"
    r"(?!<(?:REDACTED|DIGEST|SERIAL)>)(?:\[[^\]]*\]|[^\s,;]+)"
)
CERT_IDENTITY_FIELD_RE = re.compile(
    r"(?i)\b(?:subject_common_name|issuer_common_name|subjectaltname|san|names)"
    r"\s*[:=]\s*(?P<value>(?:\[[^\]]*\]|[^\r\n]+))"
)
CONTENT_DIGEST_RE = re.compile(
    r"(?i)\b(?:text_sha256|image_md5|image_sha256|icon_hash|favicon_hash|"
    r"body_sha256|response_digest)\s*[:=]\s*"
    r"(?!<DIGEST>)[0-9a-f+-]{8,}"
)
HOST_ID_RE = re.compile(
    r"(?i)(?:^|\\[rn]|[\r\n\s{])(?:hostName|hostname|machineName|sysName|fqdn|dns domain name|"
    r"dns computer name|netbios computer name|netbios domain name|target name|"
    r"hostId|vmUuid|station\.name|n4SuperId|workstation/redirector(?:-3)?|"
    r"server service)"
    r"\s*[:=]\s*(?:s:)?(?P<value>[^\s,;}\\\r\n]+)"
)
SIP_DYNAMIC_RE = re.compile(
    r"(?im)(?:\bCall-ID\s*:\s*(?!<REDACTED_TOKEN>).*?(?=\\r|\\n|\r|\n|$)|"
    r";(?:tag|branch)=(?!<REDACTED_TOKEN>)[^;>\\\r\n\s]+|"
    r"\b(?:SN|SERIAL)[/:=_-](?!<(?:SERIAL|REDACTED)>)[A-Z0-9-]{6,}|"
    r"\bMAC[/:=_-](?!<(?:SERIAL|REDACTED)>)(?:[0-9A-F]{2}[:-]?){6}\b)"
)
HTML_QUOTED_QUERY_RE = re.compile(
    r"(?is)\b(?:href|src|action)\s*=\s*(?:\"[^\"]*\?[^\"]*\"|"
    r"'[^']*\?[^']*')"
)
HTML_UNQUOTED_QUERY_RE = re.compile(
    r"(?i)(?:^|[\s<])(?:href|src|action)\s*=\s*"
    r"(?:/|https?://<(?:HOST|IP)>)[^>\s]*\?[^>\s]*"
)
LABELED_QUERY_RE = re.compile(
    r"(?i)\b(?:req_path|url)\s*[:=]\s*"
    r"(?:/|https?://<(?:HOST|IP)>|[A-Za-z0-9_.-]+/)[^\s\\]*\?[^\s\\]*|"
    r"(?i:\bLocation\s*:\s*)(?:/|https?://<(?:HOST|IP)>)[^\s\\]*\?[^\s\\]*"
)
LOCAL_USER_PATH_RE = re.compile(
    r"(?:/Users/[^/\s\"']+(?:/[^\s\"']*)?|"
    r"/home/[^/\s\"']+(?:/[^\s\"']*)?|"
    r"/data/[^/\s\"']+(?:/[^\s\"']*)?|"
    r"[A-Za-z]:\\(?:Users|users)\\[^\\\s\"']+(?:\\[^\s\"']*)?)"
)
SITE_OR_CONTACT_RE = re.compile(
    r"(?im)^\s*(?:syslocation|phone|telephone|tel|fax|address)"
    r"\s*[:=]\s*(?P<value>[^\r\n]+)$"
)
AUTHOR_CONTACT_RE = re.compile(
    r"(?im)^\s*(?:author|contact(?: person)?|administrator|admin name)"
    r"\s*[:=]\s*(?P<value>[^\r\n]+)$"
)
PHONE_CONTACT_RE = re.compile(
    r"(?i)(?:href\s*=\s*[\"']?tel:|\btel:|\bphone\s*[:=]|"
    r"\btelephone\s*[:=]|\bfax\s*[:=])\s*"
    r"(?!<REDACTED_CONTACT>)\+?[0-9][0-9(). -]{6,}[0-9]"
)
POSTAL_ADDRESS_RE = re.compile(
    r"(?i)\b\d{1,6}\s+[A-Za-z][A-Za-z .'-]{2,60}\s+"
    r"(?:Street|St\.|Road|Rd\.|Avenue|Ave\.|Boulevard|Blvd\.|Lane|Ln\.|"
    r"Drive|Dr\.)\b"
)
ISO_TEMPORAL_VALUE_RE = re.compile(
    r"(?<![0-9])\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?(?![0-9])"
)
INLINE_TEMPORAL_VALUE_RE = re.compile(
    r"(?i)\b(?:date|last-modified|expires|web_server_date)\s*[:=]\s*"
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
)
PLATFORM_DERIVED_SUMMARY_RE = re.compile(
    r"(?i)(?:\[?APP_DETECTION(?:_SUMMARY(?:_OBSERVED)?)?\]?|"
    r"\bpriv_product_info\b)"
)
INTERNAL_PROBE_FIELD_RE = re.compile(
    r"(?i)\b(?:dscan_script_name|priv_error|priv_status|req_data)\b"
)
INTERNAL_PROBE_NAME_RE = re.compile(
    r"(?i)\b(?:deep_scan_)?iot_brand[^\s,}\"']*"
)
UNREDACTED_SESSION_RE = re.compile(
    r"(?i)\b(?:g_session_tag|session(?:id|_id)?|sessid|"
    r"csrf(?:token|_token)?|nonce|pageseed)\s*[:=]\s*"
    r"(?!<REDACTED_TOKEN>)[\"']?[A-Za-z0-9_./+%=-]{6,}"
)
EMBEDDED_BEARER_RE = re.compile(
    r"(?i)\bBearer\s+(?!<REDACTED(?:_TOKEN)?>)"
    r"[A-Za-z0-9][A-Za-z0-9._~+/=-]{16,}"
)
STRUCTURED_PRIVATE_VALUE_RE = re.compile(
    r"(?ix)(?:[\"']|\b)(?:token|id_token|access_token|refresh_token|"
    r"auth_token|api_key|apikey|authkey|secret|client_secret|password|"
    r"passwd|username|user_name|login_name|account_name|hostname|"
    r"machine_name|hostid|ssid|wifi_name|serialnumber|serial_number|"
    r"deviceid|uuid|email|phone|telephone|fax)(?:[\"']|\b)\s*[:=]\s*"
    r"[\"'](?!<(?:HOST|SERIAL|UUID|REDACTED(?:_[A-Z]+)?)>)"
    r"[^\"'\r\n]{2,}[\"']"
)
STRUCTURED_CREDENTIAL_VALUE_RE = re.compile(
    r"(?ix)(?:"
    r"[\"'](?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|"
    r"password|passwd)[\"']\s*:\s*[\"']"
    r"(?!<(?:REDACTED|REDACTED_TOKEN)>)[^\"'\r\n]{8,}[\"']|"
    r"\b(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|"
    r"password|passwd)\b\s*=\s*[\"']"
    r"(?!<(?:REDACTED|REDACTED_TOKEN)>)[A-Za-z0-9_./%=-]{8,}[\"']"
    r")"
)
STRUCTURED_DEPLOYMENT_ID_RE = re.compile(
    r"(?ix)(?:[\"']|\b)[A-Za-z0-9_-]*(?:app[_-]?id|pid)"
    r"[A-Za-z0-9_-]*(?:[\"']|\b)\s*[:=]\s*[\"']"
    r"(?!<(?:REDACTED|REDACTED_ID)>)[0-9a-f]{8,}[\"']"
)
NUMERIC_HOST_PORT_RE = re.compile(
    r"(?i)(?<![0-9.])(?:\d{1,3}\.){2,3}\d{1,3}:\d{2,5}\b"
)
CONCATENATED_HOST_PORT_RE = re.compile(
    r"(?ix)<(?:HOST|IP)>\s*[\"']?\s*\+\s*[\"']?\s*:\s*\d{2,5}\b"
)
HTML_CSRF_META_RE = re.compile(
    r"(?is)<meta\b(?=[^>]*\bname\s*=\s*[\"']"
    r"(?:csrf[-_]?token|xsrf[-_]?token)[\"'])"
    r"(?=[^>]*\bcontent\s*=\s*[\"'](?!<REDACTED_TOKEN>)[^\"']+)"
)
HTML_SECRET_INPUT_RE = re.compile(
    r"(?is)<input\b(?=[^>]*(?:\btype\s*=\s*[\"']password[\"']|"
    r"\bname\s*=\s*[\"'](?:password|passwd|token|secret|username|"
    r"user_name|login|email)[\"']))"
    r"(?=[^>]*\bvalue\s*=\s*[\"'](?!<REDACTED_TOKEN>)[^\"']+)"
)
HTML_DATA_SECRET_RE = re.compile(
    r"(?is)\bdata-(?:token|api-key|secret|username|user|hostname|ssid)"
    r"\s*=\s*[\"'](?!<REDACTED_TOKEN>)[^\"']+[\"']"
)
DOCUMENT_COOKIE_RE = re.compile(
    r"(?is)\bdocument\.cookie\s*=\s*[\"']"
    r"(?!<REDACTED_TOKEN>)[^\"']{2,}[\"']"
)
KNOWN_PROVIDER_SECRET_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{20,}|(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
    r"[A-Za-z0-9_-]{10,})"
)
BASE64_BLOB_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{512,}={0,2}(?![A-Za-z0-9+/])"
)
SCREENSHOT_RAW_TITLE_RE = re.compile(
    r"(?is)(?:\[SCREENSHOT_METADATA\][^\[]*?\btitle\s*=|"
    r"SCREENSHOT_OR_PAGE_TITLE\s*:\s*title\s*=)\s*"
    r"(?!<REDACTED_TITLE>)"
)
HTML_TITLE_BLOCK_RE = re.compile(r"(?is)<title\b[^>]*>.*?</title\s*>")
VERSION_CONTEXT_RE = re.compile(
    r"(?i)(?:firmware|firmwareversion|firmware_revision|fw[_ -]?version|"
    r"software(?:[_ -](?:version|revision))?|user-agent|sonicos|"
    r"application_software_revision|server\s*:|modelnumber|"
    r"\bversion\s*[:=/]|\bappliance\s+v?|build\s*[:=]|revision\s*[:=])"
)


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"non-object at {path}:{line_no}")
            yield row


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def valid_ipv6(value: str) -> bool:
    if value.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def check_url_authorities(text: str, errors: list[str], label: str) -> None:
    for match in URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;)]}\"'")
        try:
            parts = urlsplit(raw)
        except ValueError:
            errors.append(f"malformed URL after sanitization: {label}")
            continue
        if parts.netloc != "<HOST>":
            errors.append(f"unredacted URL authority {parts.netloc!r}: {label}")


def version_occurrence_is_authorized(
    text: str,
    start: int,
    end: int,
    allowed_version_values: set[str],
    allow_standalone_version: bool = False,
) -> bool:
    """Allow address-shaped text only inside a contextual firmware Gold value."""
    folded = text.casefold()
    for value in allowed_version_values:
        if not value:
            continue
        needle = value.casefold()
        if allow_standalone_version and folded.strip() == needle:
            return True
        offset = 0
        while True:
            found = folded.find(needle, offset)
            if found < 0:
                break
            value_end = found + len(needle)
            if found <= start and end <= value_end:
                context = text[max(0, found - 120) : min(len(text), value_end + 80)]
                if VERSION_CONTEXT_RE.search(context):
                    return True
            offset = found + 1
    return False


def normalized_identity(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def certificate_value_is_public_identity(
    value: str, allowed_identity_values: set[str]
) -> bool:
    cleaned = value.strip().strip("[]").strip().strip("\"'")
    normalized = normalized_identity(cleaned)
    if not normalized:
        return False
    for allowed in allowed_identity_values:
        target = normalized_identity(allowed)
        if not target:
            continue
        if normalized == target:
            return True
        for generic in ("router", "gateway", "device", "appliance", "server"):
            if normalized in {target + generic, generic + target}:
                return True
    return False


def check_bare_hostnames(
    text: str,
    *,
    allowed_version_values: set[str],
    allow_standalone_version: bool,
    errors: list[str],
    label: str,
) -> None:
    for match in FQDN_RE.finditer(text):
        value = match.group(0)
        labels = value.rstrip(".").split(".")
        if len(labels) >= 3 or labels[-1].casefold() in PUBLIC_HOST_SUFFIXES:
            if version_occurrence_is_authorized(
                text,
                match.start(),
                match.end(),
                allowed_version_values,
                allow_standalone_version,
            ):
                continue
            errors.append(f"unredacted hostname {value!r}: {label}")


def check_evidence_privacy(
    evidence: str,
    *,
    allowed_version_values: set[str],
    allowed_identity_values: set[str] | None = None,
    allow_standalone_version: bool = False,
    errors: list[str],
    label: str,
) -> None:
    allowed_identity_values = allowed_identity_values or allowed_version_values
    simple_patterns = {
        "internal record id": INTERNAL_RECORD_RE,
        "MAC address": MAC_RE,
        "email address": EMAIL_RE,
        "UUID": UUID_RE,
        "service endpoint port": SERVICE_PORT_RE,
        "redacted host with port": REDACTED_HOST_PORT_RE,
        "port metadata": PORT_METADATA_RE,
        "embedded protocol port": PORT_FIELD_RE,
        "JSON port field": JSON_PORT_FIELD_RE,
        "serial value": SERIAL_VALUE_RE,
        "plain identifier": PLAIN_IDENTIFIER_RE,
        "XML identifier": XML_IDENTIFIER_RE,
        "sensitive header": SENSITIVE_HEADER_RE,
        "cookie continuation": COOKIE_CONTINUATION_RE,
        "public account identifier": PUBLIC_ACCOUNT_RE,
        "raw collection timestamp": RAW_TIMESTAMP_RE,
        "request query": REQUEST_QUERY_RE,
        "certificate fingerprint or serial": CERT_FINGERPRINT_RE,
        "raw content digest": CONTENT_DIGEST_RE,
        "dynamic SIP identifier": SIP_DYNAMIC_RE,
        "quoted query-bearing resource": HTML_QUOTED_QUERY_RE,
        "unquoted query-bearing resource": HTML_UNQUOTED_QUERY_RE,
        "labeled query-bearing resource": LABELED_QUERY_RE,
        "local user path": LOCAL_USER_PATH_RE,
        "telephone or fax contact": PHONE_CONTACT_RE,
        "postal address": POSTAL_ADDRESS_RE,
        "ISO collection timestamp": ISO_TEMPORAL_VALUE_RE,
        "inline temporal header": INLINE_TEMPORAL_VALUE_RE,
        "platform-derived app summary": PLATFORM_DERIVED_SUMMARY_RE,
        "private probe implementation field": INTERNAL_PROBE_FIELD_RE,
        "private product-probe name": INTERNAL_PROBE_NAME_RE,
        "unredacted session value": UNREDACTED_SESSION_RE,
        "embedded bearer credential": EMBEDDED_BEARER_RE,
        "structured private value": STRUCTURED_PRIVATE_VALUE_RE,
        "structured credential value": STRUCTURED_CREDENTIAL_VALUE_RE,
        "structured deployment identifier": STRUCTURED_DEPLOYMENT_ID_RE,
        "numeric host-port endpoint": NUMERIC_HOST_PORT_RE,
        "concatenated host-port endpoint": CONCATENATED_HOST_PORT_RE,
        "HTML CSRF token": HTML_CSRF_META_RE,
        "HTML secret input value": HTML_SECRET_INPUT_RE,
        "HTML data-secret value": HTML_DATA_SECRET_RE,
        "document cookie value": DOCUMENT_COOKIE_RE,
        "known provider credential": KNOWN_PROVIDER_SECRET_RE,
        "long binary/base64 body": BASE64_BLOB_RE,
        "unredacted screenshot title": SCREENSHOT_RAW_TITLE_RE,
    }
    for name, pattern in simple_patterns.items():
        if pattern.search(evidence):
            errors.append(f"{name} remains in {label}")
    for match in SUFFIX_PORT_FIELD_RE.finditer(evidence):
        # UPnP service identifiers such as AVTransport:1 are not endpoint
        # coordinates. All other numeric fields ending in "port" fail closed.
        field = match.group("field").casefold()
        if not field.endswith("transport") and field not in {"maxlanport", "sataport"}:
            errors.append(f"custom network-port field remains in {label}")
            break
    for match in JSON_IDENTIFIER_RE.finditer(evidence):
        value = match.group("value").strip()
        # JavaScript module maps can legitimately use keys such as `uuid`;
        # only identifier-like values are private endpoint metadata.
        if value.casefold().endswith(FILE_LIKE_SUFFIXES):
            continue
        errors.append(f"JSON identifier remains in {label}")
        break
    for match in HOST_ID_RE.finditer(evidence):
        if match.group("value") in {"<HOST>", "<IP>", "<UUID>", "<REDACTED>"}:
            continue
        errors.append(f"host identifier remains in {label}")
        break
    for match in CERT_IDENTITY_FIELD_RE.finditer(evidence):
        value = match.group("value").strip()
        if value.startswith(("<REDACTED>", "['<HOST>']", '["<HOST>"]')):
            continue
        if certificate_value_is_public_identity(value, allowed_identity_values):
            continue
        errors.append(f"certificate identity remains in {label}")
        break
    for match in HTTP_TEMPORAL_HEADER_RE.finditer(evidence):
        value = match.group("value").strip()
        if not value.startswith(("<TIME>", "<REDACTED>")):
            errors.append(f"HTTP temporal header remains in {label}")
            break
    for match in SITE_OR_CONTACT_RE.finditer(evidence):
        value = match.group("value").strip()
        if not value.startswith(
            (
                "<REDACTED",
                "<HOST>",
                "<DEVICE_NAME>",
                "http://",
                "https://",
                "/",
            )
        ):
            errors.append(f"site or contact field remains in {label}")
            break
    for match in AUTHOR_CONTACT_RE.finditer(evidence):
        if not match.group("value").strip().startswith("<REDACTED"):
            errors.append(f"author or contact identity remains in {label}")
            break
    for match in HTML_TITLE_BLOCK_RE.finditer(evidence):
        if "<REDACTED_TITLE>" not in match.group(0):
            errors.append(f"unredacted HTML title remains in {label}")
            break
    check_url_authorities(evidence, errors, label)
    check_bare_hostnames(
        evidence,
        allowed_version_values=allowed_version_values,
        allow_standalone_version=allow_standalone_version,
        errors=errors,
        label=label,
    )
    for match in IPV4_RE.finditer(evidence):
        value = match.group(0)
        if valid_ipv4(value) and not version_occurrence_is_authorized(
            evidence,
            match.start(),
            match.end(),
            allowed_version_values,
            allow_standalone_version,
        ):
            errors.append(f"unredacted IPv4 literal {value}: {label}")
    for match in IPV6_TOKEN_RE.finditer(evidence):
        value = match.group(0)
        if valid_ipv6(value):
            errors.append(f"unredacted IPv6 literal {value}: {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    args = parser.parse_args()
    root = args.benchmark
    errors: list[str] = []
    manifest_path = root / "release_manifest.json"
    if not manifest_path.is_file():
        raise SystemExit(f"missing benchmark manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    listed_files: set[Path] = set()
    for item in manifest.get("files", []):
        relative = Path(item["path"])
        path = root / relative
        listed_files.add(path)
        if not path.is_file():
            errors.append(f"missing shard: {relative}")
            continue
        if path.stat().st_size != int(item["bytes"]):
            errors.append(f"byte count mismatch: {relative}")
        if sha256(path) != item["sha256"]:
            errors.append(f"SHA-256 mismatch: {relative}")
        row_count = sum(1 for _ in iter_jsonl(path))
        if row_count != int(item["rows"]):
            errors.append(f"row count mismatch: {relative}")

    actual_shards = set((root / "records").glob("*.jsonl")) | set(
        (root / "cells").glob("*.jsonl")
    )
    if actual_shards != listed_files:
        errors.append("manifest shard set differs from on-disk shard set")

    records: dict[str, dict[str, Any]] = {}
    cells_by_record: dict[str, list[dict[str, Any]]] = defaultdict(list)
    track_records: dict[str, set[str]] = defaultdict(set)
    track_cells = Counter()
    positive = Counter()
    services: set[str] = set()
    for path in sorted((root / "records").glob("*.jsonl")):
        for row in iter_jsonl(path):
            unknown = set(row) - ALLOWED_RECORD_FIELDS
            if unknown:
                errors.append(f"unknown record fields {sorted(unknown)}: {path.name}")
            record_id = str(row.get("record_id", ""))
            if record_id in records:
                errors.append(f"duplicate record id: {record_id}")
                continue
            records[record_id] = row
            track = str(row.get("track", ""))
            track_records[track].add(record_id)
            service = str(row.get("service", "")).strip().lower()
            if service not in {"", "unknown", "none", "null", "n/a", "na", "tcp", "udp"}:
                services.add(service)
            if "port" in row or "ip" in row or "target" in row:
                errors.append(f"endpoint field in released record: {record_id}")
            evidence = str(row.get("evidence", ""))
            if hashlib.sha256(evidence.encode("utf-8")).hexdigest() != row.get(
                "evidence_sha256"
            ):
                errors.append(f"evidence digest mismatch: {record_id}")

    seen_cells: set[str] = set()
    for path in sorted((root / "cells").glob("*.jsonl")):
        for row in iter_jsonl(path):
            unknown = set(row) - ALLOWED_CELL_FIELDS
            if unknown:
                errors.append(f"unknown cell fields {sorted(unknown)}: {path.name}")
            cell_id = str(row.get("cell_id", ""))
            if cell_id in seen_cells:
                errors.append(f"duplicate cell id: {cell_id}")
            seen_cells.add(cell_id)
            record_id = str(row.get("record_id", ""))
            if record_id not in records:
                errors.append(f"orphan cell: {cell_id}")
            cells_by_record[record_id].append(row)
            track = str(row.get("track", ""))
            track_cells[track] += 1
            attribute = str(row.get("attribute", ""))
            if attribute not in ATTRIBUTES:
                errors.append(f"unknown attribute: {cell_id}")
            gold_values = row.get("gold_values")
            if not isinstance(gold_values, list):
                errors.append(f"gold_values is not a list: {cell_id}")
                gold_values = []
            if bool(gold_values) != bool(row.get("gold_supported")):
                errors.append(f"gold support/value mismatch: {cell_id}")
            positive[(track, attribute)] += bool(row.get("gold_supported"))
            for value_label, value in [('gold', item) for item in gold_values]:
                text = str(value or "")
                if URL_RE.search(text) or EMAIL_RE.search(text) or MAC_RE.search(text):
                    errors.append(f"endpoint identifier in {value_label}: {cell_id}")
                if (
                    attribute != "firmware_version"
                    and FQDN_RE.fullmatch(text)
                    and not text.casefold().endswith(FILE_LIKE_SUFFIXES)
                ):
                    errors.append(f"hostname in {value_label}: {cell_id}")
                if attribute != "firmware_version":
                    for match in IPV4_RE.finditer(text):
                        if valid_ipv4(match.group(0)):
                            errors.append(f"address-shaped {value_label}: {cell_id}")

    for record_id, record in records.items():
        cells = cells_by_record.get(record_id, [])
        attributes = sorted(str(row.get("attribute")) for row in cells)
        if attributes != sorted(ATTRIBUTES):
            errors.append(f"incomplete attribute grid: {record_id}")
        if any(row.get("track") != record.get("track") for row in cells):
            errors.append(f"track mismatch between record and cell: {record_id}")
        allowed_version_values = {
            str(value)
            for row in cells
            if row.get("attribute") == "firmware_version"
            for value in (row.get("gold_values") or [])
            if isinstance(value, str) and value
        }
        allowed_identity_values = {
            str(value)
            for row in cells
            for value in (row.get("gold_values") or [])
            if isinstance(value, str) and value
        }
        check_evidence_privacy(
            str(record.get("evidence", "")),
            allowed_version_values=allowed_version_values,
            allowed_identity_values=allowed_identity_values,
            errors=errors,
            label=record_id,
        )

    for track, expected in EXPECTED.items():
        if len(track_records[track]) != expected["records"]:
            errors.append(
                f"{track}: records {len(track_records[track])} != {expected['records']}"
            )
        if track_cells[track] != expected["cells"]:
            errors.append(
                f"{track}: cells {track_cells[track]} != {expected['cells']}"
            )
        actual_positive = {
            attribute: positive[(track, attribute)] for attribute in ATTRIBUTES
        }
        if actual_positive != expected["positive"]:
            errors.append(
                f"{track}: positive counts {actual_positive} != {expected['positive']}"
            )

    track_names = list(EXPECTED)
    for index, left in enumerate(track_names):
        for right in track_names[index + 1 :]:
            if track_records[left] & track_records[right]:
                errors.append(f"anonymous record overlap: {left}/{right}")
    if len(records) != 8_600 or len(seen_cells) != 25_800:
        errors.append(
            f"suite cardinality mismatch records={len(records)} cells={len(seen_cells)}"
        )
    if len(services) != 53:
        errors.append(f"normalized service count {len(services)} != 53")

    report = {
        "status": "PASS" if not errors else "FAIL",
        "records": len(records),
        "attribute_cells": len(seen_cells),
        "normalized_services": len(services),
        "tracks": {
            track: {
                "records": len(track_records[track]),
                "cells": track_cells[track],
                "positive": {
                    attribute: positive[(track, attribute)]
                    for attribute in ATTRIBUTES
                },
            }
            for track in EXPECTED
        },
        "errors": errors,
    }
    output = ROOT / "outputs/benchmark_gate.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

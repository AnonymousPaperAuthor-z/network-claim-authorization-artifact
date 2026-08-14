"""Rule patterns for CSA source-type span classification.

The patterns cover high-frequency network-observation evidence forms used by
VeriClaim Week 01: protocol self-reports, device banners, server headers,
component/library versions, static resources, cache artifacts, and HTML titles.
The rules are intentionally conservative; uncovered evidence remains unlabeled
so the audit sample can expose missing source types.
"""

from __future__ import annotations

import re


SOURCE_TYPES = [
    "device_banner",
    "protocol_self_report",
    "component_version",
    "server_software",
    "static_resource",
    "cache_artifact",
    "library_version",
    "screenshot_title",
]

VERSION_TOKEN = r"[vV]?\d+(?:[._-]\d+){1,5}(?:[a-zA-Z0-9._+-]*)?"

DEVICE_BANNER_RE = re.compile(
    r"\b("
    r"welcome\s+to|banner|login:|user(?:name)?:|password:|"
    r"ftp\s+server\s+ready|ssh-\d|telnet|sip/\d|rtsp/\d|"
    r"moxa|axis|apc|lancom|zte|dahua|hikvision|teltonika|qnap"
    r")\b",
    re.IGNORECASE,
)

PROTOCOL_SELF_REPORT_RE = re.compile(
    r"\b("
    r"sysdescr|snmp|onvif|getdeviceinformation|deviceinformation|"
    r"firmwareversion|firmware\s+version|software\s+version|fwver|"
    r"manufacturer|model(?:name|number)?|hardwareid|serialnumber|"
    r"bacnet|objectname|firmwarerevision|applicationsoftwarerevision|"
    r"ethernet/ip|ethernetip|identity\s+object|product\s+name|revision|"
    r"fins|controller\s+data\s+read|modbus|device\s+identification"
    r")\b",
    re.IGNORECASE,
)

COMPONENT_NAMES = [
    "apache",
    "nginx",
    "microsoft-iis",
    "iis",
    "php",
    "linux",
    "kernel",
    "openssl",
    "openssh",
    "dropbear",
    "busybox",
    "gsoap",
    "genivia",
    "sofia-sip",
    "hydra",
    "boa",
    "goahead",
    "lighttpd",
    "mini_httpd",
    "tomcat",
    "jetty",
    "proftpd",
    "pure-ftpd",
    "filezilla",
    "vsftpd",
    "ws_ftp",
]

COMPONENT_VERSION_RE = re.compile(
    r"\b(?:"
    + "|".join(re.escape(name) for name in COMPONENT_NAMES)
    + r")\b[^\r\n;,\]\[()<>]{0,24}?(?:/|\s|:|=|-)?\s*("
    + VERSION_TOKEN
    + r")",
    re.IGNORECASE,
)

SERVER_SOFTWARE_RE = re.compile(
    r"(?im)^\s*(?:server|x-powered-by|x-aspnet-version|set-cookie)\s*:\s*[^\r\n]+"
)

STATIC_RESOURCE_RE = re.compile(
    r"(?i)(?:^|[\"'\s(])"
    r"(/[A-Za-z0-9_./~:@%+-]*(?:"
    + VERSION_TOKEN
    + r")[A-Za-z0-9_./~:@%+-]*\.(?:js|css|png|gif|jpg|jpeg|svg|ico|map|html?)"
    r"|[A-Za-z0-9_.-]+[-_.]"
    + VERSION_TOKEN
    + r"\.(?:js|css|map))"
)

CACHE_ARTIFACT_RE = re.compile(
    r"(?i)("
    r"\betag\s*:\s*[\"']?[^\"'\r\n\s]{6,}"
    r"|\b(?:build|buildid|cache|cachebuster|rev|revision)\s*[:=]\s*[A-Za-z0-9._-]{4,}"
    r"|\?(?:v|ver|version|t|ts|time|cache|r|rev|_)=([A-Za-z0-9._-]{3,})"
    r"|[A-Fa-f0-9]{16,}"
    r")"
)

LIBRARY_VERSION_RE = re.compile(
    r"\b("
    r"jquery|jquery-ui|openlayers|requirejs|require\.js|bootstrap|moment|"
    r"d3|react|vue|angular|lodash|underscore|extjs|ext-all"
    r")\b[^\r\n;,\]\[()<>]{0,32}?(?:version\s*)?(?:/|\s|:|=|-)?\s*("
    + VERSION_TOKEN
    + r")",
    re.IGNORECASE,
)

HTML_TITLE_RE = re.compile(
    r"<title[^>]*>.*?</title>|^\s*(?:title|screenshot_title)\s*[:=]\s*[^\r\n]+",
    re.IGNORECASE | re.DOTALL | re.MULTILINE,
)

VERSION_LIKE_RE = re.compile(VERSION_TOKEN)

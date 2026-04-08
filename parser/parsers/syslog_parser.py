"""
CyberNest Syslog Parser.

Parses RFC 3164 and RFC 5424 syslog messages and maps to ECS fields.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.syslog")

# Syslog facility names (RFC 5424)
FACILITY_NAMES: dict[int, str] = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

# Syslog severity names (RFC 5424)
SEVERITY_NAMES: dict[int, str] = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}

# ECS severity mapping
SEVERITY_TO_ECS: dict[int, int] = {
    0: 100, 1: 90, 2: 80, 3: 70,
    4: 50, 5: 40, 6: 20, 7: 10,
}

# RFC 3164: <priority>Mmm dd HH:MM:SS hostname process[pid]: message
RFC3164_RE = re.compile(
    r"^<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"([\w.\-]+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s*"
    r"(.*)$",
    re.DOTALL,
)

# RFC 5424: <priority>version timestamp hostname appname procid msgid [structured-data] msg
RFC5424_RE = re.compile(
    r"^<(\d{1,3})>"
    r"(\d+)\s+"
    r"(\S+)\s+"
    r"([\w.\-]+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"((?:\[.*?\])*|-)\s*"
    r"(.*)$",
    re.DOTALL,
)

# Structured-data parser: [sdid key="val" key2="val2"]
SD_RE = re.compile(r'\[(\S+?)\s+(.*?)\]')
SD_PARAM_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def _decode_priority(pri: int) -> tuple[int, int, str, str]:
    """Decode syslog priority into facility and severity."""
    facility = pri >> 3
    severity = pri & 0x07
    facility_name = FACILITY_NAMES.get(facility, f"unknown({facility})")
    severity_name = SEVERITY_NAMES.get(severity, f"unknown({severity})")
    return facility, severity, facility_name, severity_name


def _parse_rfc3164_timestamp(ts_str: str) -> Optional[str]:
    """Parse RFC 3164 timestamp (Mmm dd HH:MM:SS) to ISO format."""
    try:
        # RFC 3164 doesn't include year, assume current year
        now = datetime.utcnow()
        dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
        # Handle December -> January rollover
        if dt.month > now.month + 1:
            dt = dt.replace(year=now.year - 1)
        return dt.isoformat() + "Z"
    except (ValueError, TypeError):
        return None


def _parse_structured_data(sd_str: str) -> dict[str, dict[str, str]]:
    """Parse RFC 5424 structured data."""
    result: dict[str, dict[str, str]] = {}
    if sd_str == "-" or not sd_str:
        return result

    for sd_match in SD_RE.finditer(sd_str):
        sd_id = sd_match.group(1)
        params_str = sd_match.group(2)
        params: dict[str, str] = {}
        for param_match in SD_PARAM_RE.finditer(params_str):
            params[param_match.group(1)] = param_match.group(2).replace('\\"', '"')
        result[sd_id] = params

    return result


def _is_syslog(raw_data: Any) -> bool:
    """Detect syslog format by looking for priority header."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False
    return bool(raw_str) and raw_str.lstrip().startswith("<") and re.match(r"^<\d{1,3}>", raw_str.lstrip())


@register_parser("syslog_rfc3164", detector=None, priority=40)
def parse_syslog_rfc3164(raw_data: Any) -> dict[str, Any]:
    """Parse an RFC 3164 syslog message to ECS format."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    match = RFC3164_RE.match(raw_str.strip())
    if not match:
        raise ValueError(f"Not a valid RFC 3164 syslog message: {raw_str[:100]}")

    pri = int(match.group(1))
    timestamp_str = match.group(2)
    hostname = match.group(3)
    process = match.group(4)
    pid = match.group(5)
    message = match.group(6).strip()

    facility, severity, facility_name, severity_name = _decode_priority(pri)
    ts_iso = _parse_rfc3164_timestamp(timestamp_str)

    ecs: dict[str, Any] = {
        "@timestamp": ts_iso or datetime.utcnow().isoformat() + "Z",
        "message": message,
        "raw": raw_str,
        "event": {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "action": "syslog-message",
            "outcome": "success",
            "module": "syslog",
            "dataset": "syslog.rfc3164",
            "severity": SEVERITY_TO_ECS.get(severity, 50),
        },
        "host": {
            "name": hostname,
            "hostname": hostname,
        },
        "process": {
            "name": process,
            "pid": int(pid) if pid else None,
        },
        "log": {
            "level": severity_name,
            "syslog": {
                "facility": {
                    "code": facility,
                    "name": facility_name,
                },
                "severity": {
                    "code": severity,
                    "name": severity_name,
                },
                "priority": pri,
            },
        },
        "related": {
            "hosts": [hostname],
        },
        "cybernest": {
            "parser_name": "syslog_rfc3164",
            "parse_status": "success",
            "parser_version": "1.0.0",
        },
    }
    return ecs


@register_parser("syslog_rfc5424", detector=None, priority=39)
def parse_syslog_rfc5424(raw_data: Any) -> dict[str, Any]:
    """Parse an RFC 5424 syslog message to ECS format."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    match = RFC5424_RE.match(raw_str.strip())
    if not match:
        raise ValueError(f"Not a valid RFC 5424 syslog message: {raw_str[:100]}")

    pri = int(match.group(1))
    version = match.group(2)
    timestamp_str = match.group(3)
    hostname = match.group(4)
    appname = match.group(5)
    procid = match.group(6)
    msgid = match.group(7)
    structured_data_str = match.group(8)
    message = match.group(9).strip()

    facility, severity, facility_name, severity_name = _decode_priority(pri)
    structured_data = _parse_structured_data(structured_data_str)

    # Parse ISO 8601 timestamp
    ts_iso = timestamp_str
    if ts_iso != "-":
        try:
            ts_iso = datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).isoformat() + "Z"
        except (ValueError, TypeError):
            pass

    ecs: dict[str, Any] = {
        "@timestamp": ts_iso if ts_iso != "-" else datetime.utcnow().isoformat() + "Z",
        "message": message if message else None,
        "raw": raw_str,
        "event": {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "action": "syslog-message",
            "outcome": "success",
            "module": "syslog",
            "dataset": "syslog.rfc5424",
            "severity": SEVERITY_TO_ECS.get(severity, 50),
        },
        "host": {
            "name": hostname if hostname != "-" else None,
            "hostname": hostname if hostname != "-" else None,
        },
        "process": {
            "name": appname if appname != "-" else None,
            "pid": int(procid) if procid and procid != "-" and procid.isdigit() else None,
        },
        "log": {
            "level": severity_name,
            "syslog": {
                "facility": {
                    "code": facility,
                    "name": facility_name,
                },
                "severity": {
                    "code": severity,
                    "name": severity_name,
                },
                "priority": pri,
                "version": version,
                "msgid": msgid if msgid != "-" else None,
                "structured_data": structured_data if structured_data else None,
            },
        },
        "related": {
            "hosts": [hostname] if hostname != "-" else [],
        },
        "cybernest": {
            "parser_name": "syslog_rfc5424",
            "parse_status": "success",
            "parser_version": "1.0.0",
        },
    }
    return ecs


@register_parser("syslog", detector=_is_syslog, priority=35)
def parse_syslog(raw_data: Any) -> dict[str, Any]:
    """Auto-detect and parse RFC 3164 or RFC 5424 syslog messages."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    stripped = raw_str.strip()

    # RFC 5424 has a version digit after the priority
    rfc5424_check = re.match(r"^<\d{1,3}>\d+\s", stripped)
    if rfc5424_check:
        return parse_syslog_rfc5424(raw_data)

    return parse_syslog_rfc3164(raw_data)

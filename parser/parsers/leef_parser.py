"""
CyberNest LEEF (Log Event Extended Format) Parser.

Parses IBM LEEF 1.0 and 2.0 log messages and maps to ECS fields.

LEEF 1.0: LEEF:1.0|Vendor|Product|Version|EventID|key=value\tkey=value
LEEF 2.0: LEEF:2.0|Vendor|Product|Version|EventID|delimiter|key=value...
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.leef")

# LEEF header pattern
LEEF_HEADER_RE = re.compile(
    r"^(?:.*?\s)?LEEF:(\d+\.\d+)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"(.*)$",
    re.DOTALL,
)

# LEEF 2.0 has an optional custom delimiter after the EventID
LEEF2_HEADER_RE = re.compile(
    r"^(?:.*?\s)?LEEF:2\.0\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"((?:0x[0-9a-fA-F]{2}|.))\|"
    r"(.*)$",
    re.DOTALL,
)

# Standard LEEF field-to-ECS mapping
LEEF_TO_ECS: dict[str, str] = {
    "src": "source.ip",
    "srcPort": "source.port",
    "srcMAC": "source.mac",
    "srcPreNAT": "source.nat.ip",
    "srcPostNAT": "source.nat.ip",
    "srcPreNATPort": "source.nat.port",
    "srcPostNATPort": "source.nat.port",
    "dst": "destination.ip",
    "dstPort": "destination.port",
    "dstMAC": "destination.mac",
    "dstPreNAT": "destination.nat.ip",
    "dstPostNAT": "destination.nat.ip",
    "dstPreNATPort": "destination.nat.port",
    "dstPostNATPort": "destination.nat.port",
    "proto": "network.transport",
    "srcBytes": "source.bytes",
    "dstBytes": "destination.bytes",
    "totalBytes": "network.bytes",
    "srcPackets": "source.packets",
    "dstPackets": "destination.packets",
    "totalPackets": "network.packets",
    "usrName": "user.name",
    "userName": "user.name",
    "domain": "user.domain",
    "accountName": "user.name",
    "groupName": "user.group.name",
    "policy": "rule.name",
    "action": "event.action",
    "severity": "event.severity",
    "cat": "event.category_label",
    "devTime": "@timestamp",
    "devTimeFormat": "timestamp_format",
    "resource": "url.original",
    "url": "url.full",
    "sev": "event.severity",
    "identSrc": "source.domain",
    "identHostName": "host.hostname",
    "identNetBios": "host.name",
    "identGrpName": "user.group.name",
    "identMAC": "host.mac",
    "vSrc": "source.ip",
    "vSrcName": "source.domain",
}

SEVERITY_MAP: dict[str, int] = {
    "0": 10, "1": 20, "2": 30, "3": 40, "4": 50,
    "5": 60, "6": 70, "7": 80, "8": 90, "9": 100, "10": 100,
    "Low": 30, "Medium": 50, "High": 80, "Critical": 100,
    "Info": 10, "Warning": 50,
}


def _is_leef(raw_data: Any) -> bool:
    """Detect LEEF format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False
    return "LEEF:" in raw_str


def _safe_int(val: Optional[str]) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_leef_attrs(attrs_str: str, delimiter: str = "\t") -> dict[str, str]:
    """Parse LEEF key=value attribute pairs."""
    result: dict[str, str] = {}
    if not attrs_str:
        return result

    # Split by delimiter
    pairs = attrs_str.split(delimiter)
    for pair in pairs:
        pair = pair.strip()
        if "=" in pair:
            key, _, value = pair.partition("=")
            result[key.strip()] = value.strip()

    return result


def _set_nested(d: dict, dotted_key: str, value: Any) -> None:
    """Set a value in a nested dict using dotted key notation."""
    keys = dotted_key.split(".")
    current = d
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def _parse_leef_timestamp(ts_str: Optional[str], fmt: Optional[str] = None) -> Optional[str]:
    """Parse LEEF timestamp to ISO format."""
    if not ts_str:
        return None

    # Epoch millis
    if ts_str.isdigit() and len(ts_str) >= 10:
        try:
            epoch = int(ts_str)
            if epoch > 1e12:
                epoch = epoch / 1000
            return datetime.utcfromtimestamp(epoch).isoformat() + "Z"
        except (ValueError, OSError):
            pass

    # Try given format
    if fmt:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.isoformat() + "Z"
        except (ValueError, TypeError):
            pass

    # Common formats
    for f in [
        "%b %d %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(ts_str, f)
            return dt.isoformat() + "Z"
        except ValueError:
            continue

    # ISO fallback
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).isoformat() + "Z"
    except (ValueError, TypeError):
        return ts_str


@register_parser("leef", detector=_is_leef, priority=16)
def parse_leef(raw_data: Any) -> dict[str, Any]:
    """Parse a LEEF 1.0 or 2.0 message to ECS format."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    stripped = raw_str.strip()

    # Try LEEF 2.0 first (has custom delimiter)
    delimiter = "\t"
    leef_version = "1.0"
    vendor = product = version = event_id = attrs_str = ""

    m2 = LEEF2_HEADER_RE.match(stripped)
    if m2:
        leef_version = "2.0"
        vendor = m2.group(1)
        product = m2.group(2)
        version = m2.group(3)
        event_id = m2.group(4)
        delim_raw = m2.group(5)
        attrs_str = m2.group(6)
        # Decode hex delimiter
        if delim_raw.startswith("0x"):
            try:
                delimiter = chr(int(delim_raw, 16))
            except (ValueError, TypeError):
                delimiter = "\t"
        else:
            delimiter = delim_raw
    else:
        m1 = LEEF_HEADER_RE.match(stripped)
        if not m1:
            raise ValueError(f"Not a valid LEEF message: {stripped[:100]}")
        leef_version = m1.group(1)
        vendor = m1.group(2)
        product = m1.group(3)
        version = m1.group(4)
        event_id = m1.group(5)
        attrs_str = m1.group(6)

    attrs = _parse_leef_attrs(attrs_str, delimiter)
    severity_str = attrs.get("sev", attrs.get("severity", "5"))
    ecs_severity = SEVERITY_MAP.get(severity_str, 50)

    ecs: dict[str, Any] = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "message": attrs.get("msg", f"{product}: {event_id}"),
        "raw": raw_str,
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": attrs.get("action", event_id),
            "severity": ecs_severity,
            "code": event_id,
            "module": product.lower().replace(" ", "_"),
            "dataset": f"leef.{product.lower().replace(' ', '_')}",
            "provider": vendor,
        },
        "observer": {
            "vendor": vendor,
            "product": product,
            "version": version,
        },
        "leef": {
            "version": leef_version,
            "vendor": vendor,
            "product": product,
            "product_version": version,
            "event_id": event_id,
            "attributes": attrs,
        },
    }

    # Map attributes to ECS
    related_ips: list[str] = []
    related_users: list[str] = []
    ts_format = attrs.get("devTimeFormat")

    for leef_key, leef_value in attrs.items():
        ecs_field = LEEF_TO_ECS.get(leef_key)
        if ecs_field:
            if ecs_field == "@timestamp":
                ts = _parse_leef_timestamp(leef_value, ts_format)
                if ts:
                    ecs["@timestamp"] = ts
            elif ecs_field == "event.action":
                ecs["event"]["action"] = leef_value
            elif ecs_field == "event.severity":
                ecs["event"]["severity"] = SEVERITY_MAP.get(leef_value, _safe_int(leef_value) or 50)
            elif ".port" in ecs_field or ".bytes" in ecs_field or ".packets" in ecs_field:
                _set_nested(ecs, ecs_field, _safe_int(leef_value))
            else:
                _set_nested(ecs, ecs_field, leef_value)

        if leef_key in ("src", "dst", "srcPreNAT", "dstPreNAT", "srcPostNAT", "dstPostNAT"):
            if leef_value:
                related_ips.append(leef_value)
        if leef_key in ("usrName", "userName", "accountName"):
            if leef_value:
                related_users.append(leef_value)

    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related:
        ecs["related"] = related

    ecs["cybernest"] = {
        "parser_name": "leef",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

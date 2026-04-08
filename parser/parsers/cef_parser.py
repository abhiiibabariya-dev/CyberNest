"""
CyberNest CEF (Common Event Format) Parser.

Parses CEF-formatted log messages and maps to ECS fields.
Format: CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.cef")

# CEF header pattern
CEF_HEADER_RE = re.compile(
    r"^(?:.*?\s)?CEF:(\d+)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"([^|]*)\|"
    r"(.*)$",
    re.DOTALL,
)

# Extension key=value parser — handles values with spaces (next key= starts new pair)
EXT_KV_RE = re.compile(r"(\w+)=(.*?)(?=\s\w+=|$)")

# CEF severity mapping to ECS (0-3=Low, 4-6=Medium, 7-8=High, 9-10=Critical)
CEF_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "0": (10, "informational"), "1": (20, "informational"),
    "2": (20, "low"), "3": (30, "low"),
    "4": (40, "medium"), "5": (50, "medium"), "6": (60, "medium"),
    "7": (70, "high"), "8": (80, "high"),
    "9": (90, "critical"), "10": (100, "critical"),
    "Low": (30, "low"), "Medium": (50, "medium"),
    "High": (80, "high"), "Very-High": (90, "critical"),
    "Unknown": (20, "informational"),
}

# CEF field to ECS field mapping
CEF_TO_ECS: dict[str, str] = {
    "src": "source.ip",
    "spt": "source.port",
    "smac": "source.mac",
    "shost": "source.domain",
    "sntdom": "source.domain",
    "dst": "destination.ip",
    "dpt": "destination.port",
    "dmac": "destination.mac",
    "dhost": "destination.domain",
    "dntdom": "destination.domain",
    "duser": "user.name",
    "suser": "user.effective.name",
    "duid": "user.id",
    "fname": "file.name",
    "fsize": "file.size",
    "filePath": "file.path",
    "fileHash": "file.hash.sha256",
    "request": "url.original",
    "requestURL": "url.full",
    "requestMethod": "http.request.method",
    "requestClientApplication": "user_agent.original",
    "proto": "network.transport",
    "app": "network.application",
    "in": "source.bytes",
    "out": "destination.bytes",
    "cn1": "custom_number_1",
    "cn2": "custom_number_2",
    "cn3": "custom_number_3",
    "cs1": "custom_string_1",
    "cs2": "custom_string_2",
    "cs3": "custom_string_3",
    "cs4": "custom_string_4",
    "cs5": "custom_string_5",
    "cs6": "custom_string_6",
    "act": "event.action",
    "msg": "message",
    "rt": "@timestamp",
    "end": "event.end",
    "start": "event.start",
    "cat": "event.category_label",
    "outcome": "event.outcome",
    "reason": "event.reason",
    "deviceDirection": "network.direction",
    "deviceExternalId": "observer.serial_number",
    "deviceHostName": "observer.hostname",
    "deviceAddress": "observer.ip",
    "deviceProcessName": "process.name",
    "deviceProcessId": "process.pid",
    "deviceAction": "event.action",
    "externalId": "event.id",
    "flexString1": "flex_string_1",
    "flexString2": "flex_string_2",
    "sourceTranslatedAddress": "source.nat.ip",
    "sourceTranslatedPort": "source.nat.port",
    "destinationTranslatedAddress": "destination.nat.ip",
    "destinationTranslatedPort": "destination.nat.port",
    "deviceCustomDate1": "custom_date_1",
    "deviceCustomDate2": "custom_date_2",
}


def _is_cef(raw_data: Any) -> bool:
    """Detect CEF format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False
    return "CEF:" in raw_str and raw_str.count("|") >= 7


def _unescape_cef(value: str) -> str:
    """Unescape CEF header field values."""
    return value.replace("\\|", "|").replace("\\\\", "\\").replace("\\=", "=")


def _parse_extensions(ext_str: str) -> dict[str, str]:
    """Parse CEF extension key=value pairs."""
    extensions: dict[str, str] = {}
    if not ext_str:
        return extensions

    for match in EXT_KV_RE.finditer(ext_str):
        key = match.group(1).strip()
        value = match.group(2).strip()
        extensions[key] = _unescape_cef(value)

    return extensions


def _safe_int(val: Optional[str]) -> Optional[int]:
    """Convert to int or None."""
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_cef_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """Parse CEF timestamp formats."""
    if not ts_str:
        return None

    # Try epoch millis
    if ts_str.isdigit() and len(ts_str) >= 10:
        try:
            epoch = int(ts_str)
            if epoch > 1e12:
                epoch = epoch / 1000
            dt = datetime.utcfromtimestamp(epoch)
            return dt.isoformat() + "Z"
        except (ValueError, OSError):
            pass

    # Try ISO format
    try:
        ts_str_clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str_clean)
        return dt.isoformat() + "Z"
    except (ValueError, TypeError):
        pass

    # Try common formats
    for fmt in [
        "%b %d %Y %H:%M:%S",
        "%b %d %Y %H:%M:%S.%f",
        "%b %d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.utcnow().year)
            return dt.isoformat() + "Z"
        except ValueError:
            continue

    return ts_str


def _set_nested(d: dict, dotted_key: str, value: Any) -> None:
    """Set a value in a nested dict using dotted key notation."""
    keys = dotted_key.split(".")
    current = d
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


@register_parser("cef", detector=_is_cef, priority=15)
def parse_cef(raw_data: Any) -> dict[str, Any]:
    """Parse a CEF message to ECS format.

    Args:
        raw_data: Raw CEF string or dict with 'raw'/'message' key.

    Returns:
        ECS-normalized event dictionary.
    """
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    match = CEF_HEADER_RE.match(raw_str.strip())
    if not match:
        raise ValueError(f"Not a valid CEF message: {raw_str[:100]}")

    cef_version = match.group(1)
    device_vendor = _unescape_cef(match.group(2))
    device_product = _unescape_cef(match.group(3))
    device_version = _unescape_cef(match.group(4))
    signature_id = _unescape_cef(match.group(5))
    name = _unescape_cef(match.group(6))
    severity_str = match.group(7).strip()
    extension_str = match.group(8)

    extensions = _parse_extensions(extension_str)

    # Map severity
    sev_ecs, sev_label = CEF_SEVERITY_MAP.get(severity_str, (50, "medium"))

    # Build base ECS
    ecs: dict[str, Any] = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "message": name,
        "raw": raw_str,
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": name,
            "severity": sev_ecs,
            "code": signature_id,
            "module": device_product.lower().replace(" ", "_"),
            "dataset": f"cef.{device_product.lower().replace(' ', '_')}",
            "provider": device_vendor,
        },
        "observer": {
            "vendor": device_vendor,
            "product": device_product,
            "version": device_version,
            "type": "ids" if "IDS" in device_product.upper() or "IPS" in device_product.upper() else "firewall",
        },
        "cef": {
            "version": cef_version,
            "device_vendor": device_vendor,
            "device_product": device_product,
            "device_version": device_version,
            "signature_id": signature_id,
            "name": name,
            "severity": severity_str,
            "extensions": extensions,
        },
    }

    # Map extension fields to ECS
    related_ips: list[str] = []
    related_users: list[str] = []
    related_hosts: list[str] = []

    for cef_key, cef_value in extensions.items():
        ecs_field = CEF_TO_ECS.get(cef_key)
        if ecs_field:
            if ecs_field == "@timestamp":
                ts = _parse_cef_timestamp(cef_value)
                if ts:
                    ecs["@timestamp"] = ts
            elif ecs_field == "message":
                ecs["message"] = cef_value
            elif ".port" in ecs_field or ecs_field.endswith(".bytes") or ecs_field == "file.size":
                _set_nested(ecs, ecs_field, _safe_int(cef_value))
            elif ecs_field == "process.pid":
                _set_nested(ecs, ecs_field, _safe_int(cef_value))
            elif ecs_field == "event.action":
                ecs.setdefault("event", {})["action"] = cef_value
            elif ecs_field == "event.outcome":
                ecs.setdefault("event", {})["outcome"] = cef_value
            elif ecs_field == "event.reason":
                ecs.setdefault("event", {})["reason"] = cef_value
            else:
                _set_nested(ecs, ecs_field, cef_value)

        # Track related fields
        if cef_key in ("src", "dst", "sourceTranslatedAddress", "destinationTranslatedAddress"):
            if cef_value:
                related_ips.append(cef_value)
        if cef_key in ("duser", "suser"):
            if cef_value:
                related_users.append(cef_value)
        if cef_key in ("shost", "dhost", "deviceHostName"):
            if cef_value:
                related_hosts.append(cef_value)

    # Set related fields
    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related_hosts:
        related["hosts"] = list(set(related_hosts))
    if related:
        ecs["related"] = related

    ecs["cybernest"] = {
        "parser_name": "cef",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

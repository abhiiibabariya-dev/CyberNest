"""
CyberNest JSON Log Parser.

Accepts any JSON-formatted log, passes through existing ECS fields,
and extracts common fields into ECS structure.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.json")

# Common field names found in JSON logs and their ECS mappings
COMMON_FIELD_MAP: dict[str, str] = {
    # Timestamps
    "timestamp": "@timestamp",
    "@timestamp": "@timestamp",
    "time": "@timestamp",
    "datetime": "@timestamp",
    "date": "@timestamp",
    "created_at": "@timestamp",
    "log_time": "@timestamp",
    "eventTime": "@timestamp",
    "event_time": "@timestamp",
    "ts": "@timestamp",
    # Message
    "message": "message",
    "msg": "message",
    "log": "message",
    "text": "message",
    "description": "message",
    # Source IP
    "src_ip": "source.ip",
    "source_ip": "source.ip",
    "srcip": "source.ip",
    "src_addr": "source.ip",
    "sourceAddress": "source.ip",
    "client_ip": "source.ip",
    "clientip": "source.ip",
    "remote_addr": "source.ip",
    # Source port
    "src_port": "source.port",
    "source_port": "source.port",
    "srcport": "source.port",
    # Destination IP
    "dst_ip": "destination.ip",
    "dest_ip": "destination.ip",
    "destination_ip": "destination.ip",
    "dstip": "destination.ip",
    "dst_addr": "destination.ip",
    "destinationAddress": "destination.ip",
    "server_ip": "destination.ip",
    # Destination port
    "dst_port": "destination.port",
    "dest_port": "destination.port",
    "destination_port": "destination.port",
    "dstport": "destination.port",
    "server_port": "destination.port",
    # User
    "user": "user.name",
    "username": "user.name",
    "user_name": "user.name",
    "userName": "user.name",
    "account": "user.name",
    "user_id": "user.id",
    "uid": "user.id",
    # Host
    "hostname": "host.hostname",
    "host": "host.name",
    "host_name": "host.name",
    "computer": "host.name",
    "machine": "host.name",
    # Process
    "process": "process.name",
    "process_name": "process.name",
    "pid": "process.pid",
    "process_id": "process.pid",
    "command": "process.command_line",
    "command_line": "process.command_line",
    "cmdline": "process.command_line",
    # Network
    "protocol": "network.protocol",
    "proto": "network.transport",
    # Level/severity
    "level": "log.level",
    "severity": "log.level",
    "priority": "log.level",
    "log_level": "log.level",
    "loglevel": "log.level",
    # Action
    "action": "event.action",
    "event_type": "event.action",
    "eventType": "event.action",
    # HTTP
    "method": "http.request.method",
    "http_method": "http.request.method",
    "status_code": "http.response.status_code",
    "http_status": "http.response.status_code",
    "response_code": "http.response.status_code",
    "url": "url.original",
    "request_url": "url.full",
    "uri": "url.path",
    "path": "url.path",
    "user_agent": "user_agent.original",
    "useragent": "user_agent.original",
    "referrer": "http.request.referrer",
    "referer": "http.request.referrer",
    # File
    "filename": "file.name",
    "file_path": "file.path",
    "file_name": "file.name",
    "file_size": "file.size",
    "file_hash": "file.hash.sha256",
    "md5": "file.hash.md5",
    "sha256": "file.hash.sha256",
    "sha1": "file.hash.sha1",
}


def _is_json_log(raw_data: Any) -> bool:
    """Detect JSON-formatted log."""
    if isinstance(raw_data, dict):
        return True
    if isinstance(raw_data, str):
        stripped = raw_data.strip()
        return stripped.startswith("{") and stripped.endswith("}")
    return False


def _set_nested(d: dict, dotted_key: str, value: Any) -> None:
    """Set a value in a nested dict using dotted key notation."""
    keys = dotted_key.split(".")
    current = d
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def _get_nested(d: dict, dotted_key: str) -> Any:
    """Get a value from a nested dict using dotted key notation."""
    keys = dotted_key.split(".")
    current = d
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


def _safe_int(val: Any) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_timestamp(ts: Any) -> Optional[str]:
    """Normalize timestamp to ISO format."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            if ts > 1e12:
                ts = ts / 1000
            return datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except (ValueError, OSError):
            return None
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.isoformat() + "Z"
        except (ValueError, TypeError):
            return ts
    return str(ts)


@register_parser("json", detector=_is_json_log, priority=90)
def parse_json(raw_data: Any) -> dict[str, Any]:
    """Parse a JSON log entry to ECS format.

    Passes through any existing ECS fields and maps common field
    names to their ECS equivalents.
    """
    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc}") from exc
    elif isinstance(raw_data, dict):
        data = raw_data.copy()
    else:
        raise ValueError(f"Unsupported JSON data type: {type(raw_data)}")

    raw_str = json.dumps(data, default=str) if isinstance(raw_data, dict) else raw_data

    # If the data already has ECS-style structure, pass it through
    ecs: dict[str, Any] = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "raw": raw_str,
        "event": {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "module": "json",
            "dataset": "json.generic",
        },
    }

    # Pass through existing ECS top-level fields
    ecs_top_fields = [
        "event", "source", "destination", "host", "user", "process",
        "file", "network", "dns", "http", "url", "rule", "threat",
        "agent", "log", "observer", "cloud", "container", "error",
        "service", "related",
    ]

    for field in ecs_top_fields:
        if field in data and isinstance(data[field], dict):
            if field == "event":
                ecs["event"].update(data[field])
            else:
                ecs[field] = data[field]

    # Pass through existing @timestamp/message
    if "@timestamp" in data:
        ts = _parse_timestamp(data["@timestamp"])
        if ts:
            ecs["@timestamp"] = ts
    if "message" in data and isinstance(data["message"], str):
        ecs["message"] = data["message"]
    if "tags" in data and isinstance(data["tags"], list):
        ecs["tags"] = data["tags"]
    if "labels" in data and isinstance(data["labels"], dict):
        ecs["labels"] = data["labels"]

    # Map common field names to ECS
    related_ips: list[str] = []
    related_users: list[str] = []
    related_hosts: list[str] = []

    for src_field, ecs_field in COMMON_FIELD_MAP.items():
        if src_field in data and _get_nested(ecs, ecs_field) is None:
            value = data[src_field]
            if ecs_field == "@timestamp":
                ts = _parse_timestamp(value)
                if ts and "@timestamp" not in data:
                    ecs["@timestamp"] = ts
            elif ".port" in ecs_field or ecs_field in ("process.pid", "http.response.status_code", "file.size"):
                _set_nested(ecs, ecs_field, _safe_int(value))
            else:
                _set_nested(ecs, ecs_field, value)

            # Track related
            if "source.ip" in ecs_field or "client_ip" == src_field:
                if value:
                    related_ips.append(str(value))
            if "destination.ip" in ecs_field:
                if value:
                    related_ips.append(str(value))
            if "user.name" in ecs_field:
                if value:
                    related_users.append(str(value))
            if "host.name" in ecs_field or "host.hostname" in ecs_field:
                if value:
                    related_hosts.append(str(value))

    # Store unmapped fields in labels
    mapped_keys = set(COMMON_FIELD_MAP.keys()) | set(ecs_top_fields) | {"@timestamp", "message", "tags", "labels", "ecs.version", "raw"}
    unmapped = {k: str(v) for k, v in data.items() if k not in mapped_keys and isinstance(v, (str, int, float, bool))}
    if unmapped:
        ecs.setdefault("labels", {}).update(unmapped)

    # Build related
    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related_hosts:
        related["hosts"] = list(set(related_hosts))
    if related:
        ecs.setdefault("related", {}).update(related)

    ecs["cybernest"] = {
        "parser_name": "json",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

"""CyberNest Parser — Base parser interface and ECS event builder."""

from datetime import datetime, timezone
from typing import Any
import uuid


class ECSEvent:
    """Builder for Elastic Common Schema normalized events."""

    def __init__(self):
        self._data: dict[str, Any] = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "event": {},
            "agent": {},
            "source": {},
            "destination": {},
            "user": {},
            "process": {},
            "host": {},
            "network": {},
            "rule": {},
            "file": {},
            "dns": {},
            "url": {},
            "threat": {},
            "geo": {},
            "cybernest": {
                "parse_status": "success",
                "parse_time": datetime.now(timezone.utc).isoformat(),
                "parser_version": "1.0.0",
                "event_id": str(uuid.uuid4()),
            },
        }

    def set_timestamp(self, ts: str | datetime) -> "ECSEvent":
        if isinstance(ts, datetime):
            ts = ts.isoformat()
        self._data["@timestamp"] = ts
        return self

    def set_event(self, module: str = "", category: str = "", action: str = "",
                  outcome: str = "", kind: str = "event", severity: int = 0) -> "ECSEvent":
        self._data["event"].update({
            k: v for k, v in {
                "module": module, "category": category, "action": action,
                "outcome": outcome, "kind": kind, "severity": severity,
            }.items() if v
        })
        return self

    def set_source(self, ip: str = "", port: int = 0, domain: str = "",
                   geo: dict | None = None) -> "ECSEvent":
        if ip:
            self._data["source"]["ip"] = ip
        if port:
            self._data["source"]["port"] = port
        if domain:
            self._data["source"]["domain"] = domain
        if geo:
            self._data["source"]["geo"] = geo
        return self

    def set_destination(self, ip: str = "", port: int = 0, domain: str = "") -> "ECSEvent":
        if ip:
            self._data["destination"]["ip"] = ip
        if port:
            self._data["destination"]["port"] = port
        if domain:
            self._data["destination"]["domain"] = domain
        return self

    def set_user(self, name: str = "", domain: str = "", id: str = "") -> "ECSEvent":
        if name:
            self._data["user"]["name"] = name
        if domain:
            self._data["user"]["domain"] = domain
        if id:
            self._data["user"]["id"] = id
        return self

    def set_process(self, name: str = "", pid: int = 0, command_line: str = "",
                    parent_name: str = "") -> "ECSEvent":
        if name:
            self._data["process"]["name"] = name
        if pid:
            self._data["process"]["pid"] = pid
        if command_line:
            self._data["process"]["command_line"] = command_line
        if parent_name:
            self._data["process"]["parent"] = {"name": parent_name}
        return self

    def set_host(self, hostname: str = "", ip: str = "", os_type: str = "") -> "ECSEvent":
        if hostname:
            self._data["host"]["hostname"] = hostname
        if ip:
            self._data["host"]["ip"] = ip
        if os_type:
            self._data["host"]["os"] = {"type": os_type}
        return self

    def set_network(self, protocol: str = "", direction: str = "",
                    bytes_in: int = 0, bytes_out: int = 0) -> "ECSEvent":
        if protocol:
            self._data["network"]["protocol"] = protocol
        if direction:
            self._data["network"]["direction"] = direction
        if bytes_in:
            self._data["network"]["bytes_in"] = bytes_in
        if bytes_out:
            self._data["network"]["bytes_out"] = bytes_out
        return self

    def set_rule(self, id: str = "", name: str = "", level: int = 0,
                 mitre_techniques: list[str] | None = None) -> "ECSEvent":
        if id:
            self._data["rule"]["id"] = id
        if name:
            self._data["rule"]["name"] = name
        if level:
            self._data["rule"]["level"] = level
        if mitre_techniques:
            self._data["rule"]["mitre"] = {"technique": mitre_techniques}
        return self

    def set_agent(self, id: str = "", hostname: str = "", os: str = "",
                  version: str = "") -> "ECSEvent":
        if id:
            self._data["agent"]["id"] = id
        if hostname:
            self._data["agent"]["hostname"] = hostname
        if os:
            self._data["agent"]["os"] = os
        if version:
            self._data["agent"]["version"] = version
        return self

    def set_raw(self, raw: str) -> "ECSEvent":
        self._data["raw"] = raw
        return self

    def set_field(self, dotted_key: str, value: Any) -> "ECSEvent":
        """Set any arbitrary field using dotted notation (e.g., 'file.path')."""
        keys = dotted_key.split(".")
        d = self._data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value
        return self

    def build(self) -> dict:
        # Remove empty sub-dicts
        return {k: v for k, v in self._data.items() if v}


class BaseParser:
    """Base class for all log parsers."""

    name: str = "base"
    supported_formats: list[str] = []

    def can_parse(self, raw: str) -> bool:
        raise NotImplementedError

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        raise NotImplementedError

"""
CyberNest Palo Alto Networks PAN-OS Parser.

Parses PAN-OS CSV syslog messages for log types:
TRAFFIC, THREAT, SYSTEM, CONFIG.
Maps all fields to ECS.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.palo_alto")

# PAN-OS syslog header pattern (before CSV):
# <priority>date time hostname PanOS_type: field1,field2,...
PANOS_SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?\s*(?:\S+\s+\d+\s+\d+:\d+:\d+\s+)?(\S+)\s+\d+,(.+)$",
    re.DOTALL,
)

# TRAFFIC log fields (PAN-OS 10.x)
TRAFFIC_FIELDS = [
    "receive_time", "serial_number", "type", "threat_content_type", "future_use1",
    "generated_time", "source_ip", "destination_ip", "nat_source_ip", "nat_destination_ip",
    "rule_name", "source_user", "destination_user", "application", "virtual_system",
    "source_zone", "destination_zone", "inbound_interface", "outbound_interface", "log_action",
    "future_use2", "session_id", "repeat_count", "source_port", "destination_port",
    "nat_source_port", "nat_destination_port", "flags", "protocol", "action",
    "bytes", "bytes_sent", "bytes_received", "packets", "start_time",
    "elapsed_time", "category", "future_use3", "sequence_number", "action_flags",
    "source_location", "destination_location", "future_use4", "packets_sent", "packets_received",
    "session_end_reason", "device_group_hierarchy_l1", "device_group_hierarchy_l2",
    "device_group_hierarchy_l3", "device_group_hierarchy_l4", "virtual_system_name",
    "device_name", "action_source", "source_vm_uuid", "destination_vm_uuid",
    "tunnel_id_imsi", "monitor_tag_imei", "parent_session_id", "parent_start_time",
    "tunnel_type", "sctp_association_id", "sctp_chunks", "sctp_chunks_sent", "sctp_chunks_received",
    "uuid_rule", "http2_connection", "app_flap_count", "policy_id", "link_switches",
    "sd_wan_cluster", "sd_wan_device_type", "sd_wan_cluster_type", "sd_wan_site",
    "dynamic_user_group_name", "xff_address", "source_device_category",
    "source_device_profile", "source_device_model", "source_device_vendor", "source_device_os_family",
    "source_device_os_version", "source_hostname", "source_mac_address",
    "destination_device_category", "destination_device_profile", "destination_device_model",
    "destination_device_vendor", "destination_device_os_family", "destination_device_os_version",
    "destination_hostname", "destination_mac_address", "container_id", "pod_namespace",
    "pod_name", "source_edl", "destination_edl", "host_id",
    "serial_number_2", "source_dag", "destination_dag", "session_owner",
    "high_res_timestamp", "a_slice_service_type", "a_slice_differentiator",
    "application_subcategory", "application_category", "application_technology",
    "application_risk", "application_characteristic", "application_container",
    "application_tunneled", "application_saas", "application_sanctioned_state",
    "offloaded",
]

# THREAT log fields
THREAT_FIELDS = [
    "receive_time", "serial_number", "type", "threat_content_type", "future_use1",
    "generated_time", "source_ip", "destination_ip", "nat_source_ip", "nat_destination_ip",
    "rule_name", "source_user", "destination_user", "application", "virtual_system",
    "source_zone", "destination_zone", "inbound_interface", "outbound_interface", "log_action",
    "future_use2", "session_id", "repeat_count", "source_port", "destination_port",
    "nat_source_port", "nat_destination_port", "flags", "protocol", "action",
    "url_filename", "threat_id", "category", "severity", "direction",
    "sequence_number", "action_flags", "source_location", "destination_location",
    "future_use3", "content_type", "pcap_id", "file_digest", "cloud",
    "url_index", "user_agent", "file_type", "xff", "referrer",
    "sender", "subject", "recipient", "report_id", "device_group_hierarchy_l1",
    "device_group_hierarchy_l2", "device_group_hierarchy_l3", "device_group_hierarchy_l4",
    "virtual_system_name", "device_name", "future_use4", "source_vm_uuid",
    "destination_vm_uuid", "http_method", "tunnel_id_imsi", "monitor_tag_imei",
    "parent_session_id", "parent_start_time", "tunnel_type", "threat_category",
    "content_version", "future_use5", "sctp_association_id", "payload_protocol_id",
    "http_headers", "url_category_list", "uuid_rule", "http2_connection",
    "dynamic_user_group_name", "xff_address", "source_device_category",
    "source_device_profile", "source_device_model", "source_device_vendor",
    "source_device_os_family", "source_device_os_version", "source_hostname",
    "source_mac_address", "destination_device_category", "destination_device_profile",
    "destination_device_model", "destination_device_vendor", "destination_device_os_family",
    "destination_device_os_version", "destination_hostname", "destination_mac_address",
    "container_id", "pod_namespace", "pod_name", "source_edl", "destination_edl",
    "host_id", "serial_number_2", "domain_edl", "source_dag", "destination_dag",
    "partial_hash", "high_res_timestamp", "reason", "justification",
    "nssai_sst", "subcategory_of_app", "category_of_app", "technology_of_app",
    "risk_of_app", "characteristic_of_app", "container_of_app",
    "tunneled_app", "saas_of_app", "sanctioned_state_of_app",
]

SEVERITY_MAP: dict[str, int] = {
    "informational": 20, "low": 30, "medium": 50,
    "high": 70, "critical": 90,
}


def _is_palo_alto(raw_data: Any) -> bool:
    """Detect PAN-OS CSV syslog format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False

    if not raw_str:
        return False

    # Look for PAN-OS signature: comma-separated with TRAFFIC/THREAT/SYSTEM/CONFIG type
    parts = raw_str.split(",")
    if len(parts) >= 5:
        for i, part in enumerate(parts[:5]):
            if part.strip() in ("TRAFFIC", "THREAT", "SYSTEM", "CONFIG"):
                return True
    return False


def _safe_int(val: Optional[str]) -> Optional[int]:
    if not val or val == "-" or val == "0" and False:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_csv_line(line: str) -> list[str]:
    """Parse a CSV line handling quoted fields."""
    reader = csv.reader(io.StringIO(line))
    for row in reader:
        return row
    return line.split(",")


def _parse_panos_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """Parse PAN-OS timestamp."""
    if not ts_str or ts_str == "-":
        return None
    for fmt in [
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%m/%d/%Y %H:%M:%S",
    ]:
        try:
            return datetime.strptime(ts_str, fmt).isoformat() + "Z"
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).isoformat() + "Z"
    except (ValueError, TypeError):
        return ts_str


def _fields_to_dict(values: list[str], field_names: list[str]) -> dict[str, str]:
    """Map CSV values to field names."""
    result: dict[str, str] = {}
    for i, name in enumerate(field_names):
        result[name] = values[i].strip() if i < len(values) else ""
    return result


def _parse_traffic(fields: dict[str, str]) -> dict[str, Any]:
    """Parse TRAFFIC log to ECS."""
    action = fields.get("action", "allow").lower()
    outcome = "success" if action in ("allow", "allow-url") else "failure"

    ecs: dict[str, Any] = {
        "@timestamp": _parse_panos_timestamp(fields.get("generated_time")) or datetime.utcnow().isoformat() + "Z",
        "message": f"PAN-OS TRAFFIC: {fields.get('source_ip', '')}:{fields.get('source_port', '')} -> {fields.get('destination_ip', '')}:{fields.get('destination_port', '')} {action} ({fields.get('application', '')})",
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["connection", "allowed" if outcome == "success" else "denied"],
            "action": action,
            "outcome": outcome,
            "severity": 20 if outcome == "success" else 50,
            "module": "panw",
            "dataset": "panw.traffic",
            "duration": (_safe_int(fields.get("elapsed_time")) or 0) * 1_000_000_000,
        },
        "source": {
            "ip": fields.get("source_ip") or None,
            "port": _safe_int(fields.get("source_port")),
            "bytes": _safe_int(fields.get("bytes_sent")),
            "packets": _safe_int(fields.get("packets_sent")),
            "nat": {
                "ip": fields.get("nat_source_ip") or None,
                "port": _safe_int(fields.get("nat_source_port")),
            },
            "geo": {"name": fields.get("source_location")} if fields.get("source_location") else None,
        },
        "destination": {
            "ip": fields.get("destination_ip") or None,
            "port": _safe_int(fields.get("destination_port")),
            "bytes": _safe_int(fields.get("bytes_received")),
            "packets": _safe_int(fields.get("packets_received")),
            "nat": {
                "ip": fields.get("nat_destination_ip") or None,
                "port": _safe_int(fields.get("nat_destination_port")),
            },
            "geo": {"name": fields.get("destination_location")} if fields.get("destination_location") else None,
        },
        "network": {
            "transport": fields.get("protocol", "").lower() if fields.get("protocol") else None,
            "application": fields.get("application") or None,
            "bytes": _safe_int(fields.get("bytes")),
            "packets": _safe_int(fields.get("packets")),
            "direction": "inbound" if fields.get("direction", "").lower() == "client-to-server" else "outbound",
        },
        "user": {
            "name": fields.get("source_user") or None,
        },
        "rule": {
            "name": fields.get("rule_name") or None,
            "id": fields.get("uuid_rule") or None,
        },
        "observer": {
            "hostname": fields.get("device_name") or None,
            "serial_number": fields.get("serial_number") or None,
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "type": "firewall",
        },
    }

    ecs["panw"] = {
        "log_type": "TRAFFIC",
        "session_id": fields.get("session_id"),
        "repeat_count": _safe_int(fields.get("repeat_count")),
        "source_zone": fields.get("source_zone"),
        "destination_zone": fields.get("destination_zone"),
        "inbound_interface": fields.get("inbound_interface"),
        "outbound_interface": fields.get("outbound_interface"),
        "session_end_reason": fields.get("session_end_reason"),
        "virtual_system": fields.get("virtual_system"),
        "category": fields.get("category"),
        "start_time": _parse_panos_timestamp(fields.get("start_time")),
    }

    return ecs


def _parse_threat(fields: dict[str, str]) -> dict[str, Any]:
    """Parse THREAT log to ECS."""
    action = fields.get("action", "alert").lower()
    severity_str = fields.get("severity", "medium").lower()
    severity = SEVERITY_MAP.get(severity_str, 50)
    threat_id_raw = fields.get("threat_id", "")
    threat_name = ""
    threat_id = ""
    if "(" in threat_id_raw:
        threat_name = threat_id_raw.split("(")[0].strip()
        threat_id = threat_id_raw.split("(")[-1].rstrip(")")
    else:
        threat_name = threat_id_raw
        threat_id = threat_id_raw

    outcome = "success" if action in ("alert", "allow", "continue") else "failure"

    ecs: dict[str, Any] = {
        "@timestamp": _parse_panos_timestamp(fields.get("generated_time")) or datetime.utcnow().isoformat() + "Z",
        "message": f"PAN-OS THREAT: {threat_name} ({threat_id}) {fields.get('source_ip', '')} -> {fields.get('destination_ip', '')}",
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "network"],
            "type": ["denied"] if action in ("drop", "reset-both", "reset-client", "reset-server", "block-url", "block-ip", "sinkhole") else ["allowed"],
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "module": "panw",
            "dataset": "panw.threat",
        },
        "rule": {
            "name": fields.get("rule_name") or None,
            "id": threat_id,
            "description": threat_name,
            "category": fields.get("threat_category") or fields.get("category") or None,
        },
        "source": {
            "ip": fields.get("source_ip") or None,
            "port": _safe_int(fields.get("source_port")),
            "nat": {
                "ip": fields.get("nat_source_ip") or None,
                "port": _safe_int(fields.get("nat_source_port")),
            },
        },
        "destination": {
            "ip": fields.get("destination_ip") or None,
            "port": _safe_int(fields.get("destination_port")),
            "nat": {
                "ip": fields.get("nat_destination_ip") or None,
                "port": _safe_int(fields.get("nat_destination_port")),
            },
        },
        "network": {
            "transport": fields.get("protocol", "").lower() if fields.get("protocol") else None,
            "application": fields.get("application") or None,
            "direction": fields.get("direction", "").lower() if fields.get("direction") else None,
        },
        "user": {"name": fields.get("source_user") or None},
        "observer": {
            "hostname": fields.get("device_name") or None,
            "serial_number": fields.get("serial_number") or None,
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "type": "firewall",
        },
    }

    # HTTP fields
    if fields.get("url_filename"):
        ecs["url"] = {"original": fields["url_filename"]}
    if fields.get("http_method"):
        ecs.setdefault("http", {})["request"] = {"method": fields["http_method"]}
    if fields.get("user_agent"):
        ecs["user_agent"] = {"original": fields["user_agent"]}
    if fields.get("referrer"):
        ecs.setdefault("http", {}).setdefault("request", {})["referrer"] = fields["referrer"]
    if fields.get("xff"):
        ecs.setdefault("network", {})["forwarded_ip"] = fields["xff"]

    # File fields
    if fields.get("file_digest"):
        ecs["file"] = {
            "hash": {"sha256": fields["file_digest"]},
            "type": fields.get("file_type"),
        }

    # Threat content type subtype
    content_type = fields.get("threat_content_type", "")
    ecs["panw"] = {
        "log_type": "THREAT",
        "sub_type": content_type,
        "session_id": fields.get("session_id"),
        "threat_id": threat_id,
        "threat_name": threat_name,
        "severity": severity_str,
        "source_zone": fields.get("source_zone"),
        "destination_zone": fields.get("destination_zone"),
        "pcap_id": fields.get("pcap_id"),
        "content_version": fields.get("content_version"),
    }

    return ecs


def _parse_system(fields: dict[str, str]) -> dict[str, Any]:
    """Parse SYSTEM log to ECS."""
    # System logs have fewer fields, use minimal parsing
    ecs: dict[str, Any] = {
        "@timestamp": _parse_panos_timestamp(fields.get("generated_time") or fields.get("receive_time")) or datetime.utcnow().isoformat() + "Z",
        "message": f"PAN-OS SYSTEM: {fields.get('threat_content_type', '')} - {fields.get('url_filename', fields.get('description', ''))}",
        "event": {
            "kind": "event",
            "category": ["host"],
            "type": ["info"],
            "action": fields.get("threat_content_type", "system"),
            "severity": 30,
            "module": "panw",
            "dataset": "panw.system",
        },
        "observer": {
            "hostname": fields.get("device_name") or None,
            "serial_number": fields.get("serial_number") or None,
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "type": "firewall",
        },
        "panw": {
            "log_type": "SYSTEM",
            "sub_type": fields.get("threat_content_type"),
            "virtual_system": fields.get("virtual_system"),
        },
    }
    return ecs


def _parse_config(fields: dict[str, str]) -> dict[str, Any]:
    """Parse CONFIG log to ECS."""
    ecs: dict[str, Any] = {
        "@timestamp": _parse_panos_timestamp(fields.get("generated_time") or fields.get("receive_time")) or datetime.utcnow().isoformat() + "Z",
        "message": f"PAN-OS CONFIG: {fields.get('threat_content_type', '')} by {fields.get('source_user', '')}",
        "event": {
            "kind": "event",
            "category": ["configuration"],
            "type": ["change"],
            "action": fields.get("threat_content_type", "config-change"),
            "outcome": "success",
            "severity": 40,
            "module": "panw",
            "dataset": "panw.config",
        },
        "user": {
            "name": fields.get("source_user") or None,
        },
        "source": {
            "ip": fields.get("source_ip") or None,
        },
        "observer": {
            "hostname": fields.get("device_name") or None,
            "serial_number": fields.get("serial_number") or None,
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS",
            "type": "firewall",
        },
        "panw": {
            "log_type": "CONFIG",
            "sub_type": fields.get("threat_content_type"),
            "virtual_system": fields.get("virtual_system"),
        },
    }
    return ecs


_LOG_TYPE_PARSERS = {
    "TRAFFIC": (_parse_traffic, TRAFFIC_FIELDS),
    "THREAT": (_parse_threat, THREAT_FIELDS),
    "SYSTEM": (_parse_system, TRAFFIC_FIELDS),
    "CONFIG": (_parse_config, TRAFFIC_FIELDS),
}


@register_parser("palo_alto", detector=_is_palo_alto, priority=22)
def parse_palo_alto(raw_data: Any) -> dict[str, Any]:
    """Parse a Palo Alto PAN-OS CSV syslog to ECS format."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    stripped = raw_str.strip()

    # Strip syslog header if present
    csv_data = stripped
    match = PANOS_SYSLOG_RE.match(stripped)
    if match:
        csv_data = match.group(2)

    # Parse CSV
    values = _parse_csv_line(csv_data)
    if len(values) < 5:
        raise ValueError(f"Not enough PAN-OS CSV fields: {len(values)}")

    # Detect log type (field index 2 is 'type' for standard PAN-OS)
    log_type = None
    for i, val in enumerate(values[:5]):
        if val.strip() in ("TRAFFIC", "THREAT", "SYSTEM", "CONFIG"):
            log_type = val.strip()
            break

    if not log_type:
        raise ValueError(f"Unknown PAN-OS log type in: {csv_data[:100]}")

    parser_func, field_names = _LOG_TYPE_PARSERS.get(log_type, (_parse_system, TRAFFIC_FIELDS))
    fields = _fields_to_dict(values, field_names)
    ecs = parser_func(fields)

    ecs["raw"] = raw_str

    # Related fields
    related_ips: list[str] = []
    for key in ("source_ip", "destination_ip", "nat_source_ip", "nat_destination_ip"):
        ip = fields.get(key)
        if ip and ip != "0.0.0.0" and ip != "-":
            related_ips.append(ip)
    related_users: list[str] = []
    for key in ("source_user", "destination_user"):
        u = fields.get(key)
        if u and u != "-":
            related_users.append(u)
    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related:
        ecs["related"] = related

    ecs["cybernest"] = {
        "parser_name": "palo_alto",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

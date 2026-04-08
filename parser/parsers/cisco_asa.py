"""
CyberNest Cisco ASA Parser.

Parses Cisco ASA syslog messages in %ASA-severity-msgid format.
Handles 50+ message IDs including connection, deny, NAT, and security events.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.cisco_asa")

# Cisco ASA syslog pattern: %ASA-severity-msgid: message
# Optionally preceded by syslog header
ASA_RE = re.compile(
    r"(?:^.*?)?"
    r"%ASA-(\d)-(\d{6}):\s*(.*)$",
    re.DOTALL,
)

# Alternative with timestamp/hostname prefix
ASA_SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?"
    r"(?:(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+)?"
    r"(?:(\S+)\s+)?"
    r"%ASA-(\d)-(\d{6}):\s*(.*)$",
    re.DOTALL,
)

# ASA severity to ECS severity mapping (ASA uses 0-7)
ASA_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "0": (100, "emergency"),
    "1": (90, "alert"),
    "2": (80, "critical"),
    "3": (70, "error"),
    "4": (50, "warning"),
    "5": (40, "notification"),
    "6": (20, "informational"),
    "7": (10, "debug"),
}

# IP:port extraction patterns
IP_PORT_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)")
IP_ONLY_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
IFACE_IP_PORT_RE = re.compile(r"(\w+):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d+)")

# ----- Per-MsgID parsers ---------------------------------------------------

def _safe_int(val: Optional[str]) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _extract_ip_port_pairs(msg: str) -> dict[str, Any]:
    """Extract source/destination IP:port from standard ASA message patterns."""
    result: dict[str, Any] = {"source": {}, "destination": {}}
    iface_matches = IFACE_IP_PORT_RE.findall(msg)

    if len(iface_matches) >= 2:
        result["source"] = {
            "ip": iface_matches[0][1],
            "port": _safe_int(iface_matches[0][2]),
        }
        result["destination"] = {
            "ip": iface_matches[1][1],
            "port": _safe_int(iface_matches[1][2]),
        }
        result["_src_iface"] = iface_matches[0][0]
        result["_dst_iface"] = iface_matches[1][0]
    elif len(iface_matches) == 1:
        result["source"] = {
            "ip": iface_matches[0][1],
            "port": _safe_int(iface_matches[0][2]),
        }
        result["_src_iface"] = iface_matches[0][0]
        # Try to find remaining IP:port
        remaining = msg[msg.index(iface_matches[0][1]) + len(iface_matches[0][1]):]
        ip_port = IP_PORT_RE.search(remaining)
        if ip_port:
            result["destination"] = {
                "ip": ip_port.group(1),
                "port": _safe_int(ip_port.group(2)),
            }
    else:
        ip_port_matches = IP_PORT_RE.findall(msg)
        if len(ip_port_matches) >= 2:
            result["source"] = {"ip": ip_port_matches[0][0], "port": _safe_int(ip_port_matches[0][1])}
            result["destination"] = {"ip": ip_port_matches[1][0], "port": _safe_int(ip_port_matches[1][1])}
        elif len(ip_port_matches) == 1:
            result["source"] = {"ip": ip_port_matches[0][0], "port": _safe_int(ip_port_matches[0][1])}
        else:
            ips = IP_ONLY_RE.findall(msg)
            if len(ips) >= 2:
                result["source"] = {"ip": ips[0]}
                result["destination"] = {"ip": ips[1]}
            elif len(ips) == 1:
                result["source"] = {"ip": ips[0]}

    return result


# Connection built/teardown: 302013-302016, 302020-302021
def _parse_connection(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse connection built/teardown messages (302013-302021)."""
    is_built = msg_id in ("302013", "302015", "302020")
    extracted = _extract_ip_port_pairs(msg)

    # Extract protocol
    proto_match = re.search(r"\b(TCP|UDP|ICMP|GRE)\b", msg, re.IGNORECASE)
    protocol = proto_match.group(1).lower() if proto_match else None

    # Extract duration and bytes for teardown
    duration_match = re.search(r"duration\s+(\d+:\d+:\d+)", msg)
    bytes_match = re.search(r"bytes\s+(\d+)", msg)

    action = "connection-started" if is_built else "connection-finished"
    event_types = ["start", "connection"] if is_built else ["end", "connection"]

    result: dict[str, Any] = {
        "event": {
            "category": ["network"],
            "type": event_types,
            "action": action,
            "outcome": "success",
        },
        "network": {
            "transport": protocol,
        },
        "source": extracted.get("source", {}),
        "destination": extracted.get("destination", {}),
    }

    if duration_match:
        parts = duration_match.group(1).split(":")
        total_secs = int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
        result["event"]["duration"] = total_secs * 1_000_000_000
    if bytes_match:
        result["network"]["bytes"] = _safe_int(bytes_match.group(1))

    return result


# Deny messages: 106001, 106006, 106007, 106014, 106015, 106023, 106100
def _parse_deny(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse deny/drop messages."""
    extracted = _extract_ip_port_pairs(msg)
    proto_match = re.search(r"\b(TCP|UDP|ICMP|GRE|IP)\b", msg, re.IGNORECASE)
    protocol = proto_match.group(1).lower() if proto_match else None

    # Extract access-group/ACL
    acl_match = re.search(r'access-(?:group|list)\s+"?(\S+?)"?\s', msg)
    acl_name = acl_match.group(1) if acl_match else None

    return {
        "event": {
            "kind": "alert" if msg_id in ("106023", "106100") else "event",
            "category": ["network"],
            "type": ["denied"],
            "action": "firewall-deny",
            "outcome": "failure",
        },
        "network": {
            "transport": protocol,
        },
        "rule": {
            "name": acl_name,
        },
        "source": extracted.get("source", {}),
        "destination": extracted.get("destination", {}),
    }


# AAA/Authentication: 109005-109008, 113004-113005, 113012-113019
def _parse_auth(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse authentication messages."""
    user_match = re.search(r"user\s+'?([^']+)'?", msg, re.IGNORECASE)
    user = user_match.group(1).strip() if user_match else None
    ip_match = IP_ONLY_RE.search(msg)
    src_ip = ip_match.group(1) if ip_match else None

    is_success = any(x in msg.lower() for x in ["authentication succeeded", "successful", "accepted"])
    outcome = "success" if is_success else "failure"

    return {
        "event": {
            "category": ["authentication"],
            "type": ["start"],
            "action": "user-authentication",
            "outcome": outcome,
        },
        "user": {"name": user},
        "source": {"ip": src_ip},
    }


# NAT: 305011, 305012
def _parse_nat(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse NAT messages."""
    extracted = _extract_ip_port_pairs(msg)
    is_built = msg_id == "305011"

    return {
        "event": {
            "category": ["network"],
            "type": ["start" if is_built else "end"],
            "action": "nat-built" if is_built else "nat-teardown",
            "outcome": "success",
        },
        "source": extracted.get("source", {}),
        "destination": extracted.get("destination", {}),
    }


# URL/Content: 304001, 304002
def _parse_url(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse URL access messages."""
    ip_match = IP_ONLY_RE.search(msg)
    src_ip = ip_match.group(1) if ip_match else None
    url_match = re.search(r"URL\s+(\S+)", msg)
    url = url_match.group(1) if url_match else None
    user_match = re.search(r"user\s+'?([^']+)'?", msg, re.IGNORECASE)
    user = user_match.group(1).strip() if user_match else None

    is_denied = msg_id == "304002" or "denied" in msg.lower()

    return {
        "event": {
            "category": ["web", "network"],
            "type": ["denied" if is_denied else "allowed"],
            "action": "url-denied" if is_denied else "url-allowed",
            "outcome": "failure" if is_denied else "success",
        },
        "url": {"original": url},
        "source": {"ip": src_ip},
        "user": {"name": user},
    }


# TCP/Conn issues: 710003, 710005
def _parse_tcp_access(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse TCP access messages."""
    extracted = _extract_ip_port_pairs(msg)
    is_permitted = "permitted" in msg.lower()

    return {
        "event": {
            "category": ["network"],
            "type": ["allowed" if is_permitted else "denied"],
            "action": "tcp-access-permitted" if is_permitted else "tcp-access-denied",
            "outcome": "success" if is_permitted else "failure",
        },
        "source": extracted.get("source", {}),
        "destination": extracted.get("destination", {}),
    }


# VPN / Tunnel: 711001, 713228
def _parse_vpn(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse VPN/tunnel messages."""
    ip_match = IP_ONLY_RE.search(msg)
    src_ip = ip_match.group(1) if ip_match else None
    user_match = re.search(r"user\s+'?([^']+)'?", msg, re.IGNORECASE)
    user = user_match.group(1).strip() if user_match else None

    return {
        "event": {
            "category": ["network", "session"],
            "type": ["start"],
            "action": "vpn-session",
            "outcome": "success",
        },
        "source": {"ip": src_ip},
        "user": {"name": user},
    }


# Threat detection: 733100
def _parse_threat_detection(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse threat detection rate-limit messages."""
    ip_match = IP_ONLY_RE.search(msg)
    src_ip = ip_match.group(1) if ip_match else None

    return {
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "network"],
            "type": ["denied"],
            "action": "threat-detection-triggered",
            "outcome": "failure",
            "severity": 80,
        },
        "source": {"ip": src_ip},
        "rule": {"name": "threat-detection"},
    }


# Failover: 104001-104004
def _parse_failover(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse failover messages."""
    return {
        "event": {
            "category": ["host"],
            "type": ["change"],
            "action": "failover-state-change",
            "outcome": "success",
        },
    }


# Interface: 411001, 411002
def _parse_interface(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse interface state messages."""
    return {
        "event": {
            "category": ["network"],
            "type": ["change"],
            "action": "interface-state-change",
        },
    }


# Routing: 611101-611102
def _parse_routing(msg_id: str, msg: str) -> dict[str, Any]:
    """Parse routing messages."""
    return {
        "event": {
            "category": ["network"],
            "type": ["info"],
            "action": "routing-update",
        },
    }


# Map message IDs to parser functions
_MSG_ID_PARSERS: dict[str, Any] = {}

# Connection built/teardown
for _id in ("302013", "302014", "302015", "302016", "302020", "302021"):
    _MSG_ID_PARSERS[_id] = _parse_connection

# Deny messages
for _id in ("106001", "106006", "106007", "106014", "106015", "106023", "106100"):
    _MSG_ID_PARSERS[_id] = _parse_deny

# Authentication
for _id in ("109005", "109006", "109007", "109008", "113004", "113005",
            "113012", "113013", "113014", "113015", "113016", "113017",
            "113018", "113019"):
    _MSG_ID_PARSERS[_id] = _parse_auth

# NAT
for _id in ("305011", "305012"):
    _MSG_ID_PARSERS[_id] = _parse_nat

# URL
for _id in ("304001", "304002"):
    _MSG_ID_PARSERS[_id] = _parse_url

# TCP access
for _id in ("710003", "710005"):
    _MSG_ID_PARSERS[_id] = _parse_tcp_access

# VPN
for _id in ("711001", "713228"):
    _MSG_ID_PARSERS[_id] = _parse_vpn

# Threat detection
_MSG_ID_PARSERS["733100"] = _parse_threat_detection

# Failover
for _id in ("104001", "104002", "104003", "104004"):
    _MSG_ID_PARSERS[_id] = _parse_failover

# Interface
for _id in ("411001", "411002"):
    _MSG_ID_PARSERS[_id] = _parse_interface

# Routing
for _id in ("611101", "611102"):
    _MSG_ID_PARSERS[_id] = _parse_routing

# Additional commonly seen IDs
# Conn permit/deny
for _id in ("106011", "106012", "106013", "106017", "106018", "106020",
            "106021", "106022", "106027"):
    _MSG_ID_PARSERS[_id] = _parse_deny

# More connection tracking
for _id in ("302017", "302018", "302019"):
    _MSG_ID_PARSERS[_id] = _parse_connection

# IPS/IDS
_MSG_ID_PARSERS["400000"] = _parse_threat_detection
_MSG_ID_PARSERS["400001"] = _parse_threat_detection
_MSG_ID_PARSERS["400004"] = _parse_threat_detection
_MSG_ID_PARSERS["400007"] = _parse_threat_detection
_MSG_ID_PARSERS["400010"] = _parse_threat_detection
_MSG_ID_PARSERS["400013"] = _parse_threat_detection
_MSG_ID_PARSERS["400023"] = _parse_threat_detection
_MSG_ID_PARSERS["400024"] = _parse_threat_detection
_MSG_ID_PARSERS["400025"] = _parse_threat_detection
_MSG_ID_PARSERS["400026"] = _parse_threat_detection
_MSG_ID_PARSERS["400027"] = _parse_threat_detection
_MSG_ID_PARSERS["400028"] = _parse_threat_detection


def _is_cisco_asa(raw_data: Any) -> bool:
    """Detect Cisco ASA syslog format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False
    return "%ASA-" in raw_str


@register_parser("cisco_asa", detector=_is_cisco_asa, priority=21)
def parse_cisco_asa(raw_data: Any) -> dict[str, Any]:
    """Parse a Cisco ASA syslog message to ECS format."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    stripped = raw_str.strip()

    # Try full syslog pattern first
    match = ASA_SYSLOG_RE.match(stripped)
    if match:
        syslog_ts = match.group(1)
        hostname = match.group(2)
        severity = match.group(3)
        msg_id = match.group(4)
        message = match.group(5)
    else:
        match = ASA_RE.search(stripped)
        if not match:
            raise ValueError(f"Not a valid Cisco ASA syslog: {stripped[:100]}")
        syslog_ts = None
        hostname = None
        severity = match.group(1)
        msg_id = match.group(2)
        message = match.group(3)

    sev_ecs, sev_label = ASA_SEVERITY_MAP.get(severity, (50, "warning"))

    # Parse timestamp
    ts = None
    if syslog_ts:
        try:
            now = datetime.utcnow()
            dt = datetime.strptime(f"{now.year} {syslog_ts}", "%Y %b %d %H:%M:%S")
            ts = dt.isoformat() + "Z"
        except ValueError:
            pass

    # Build base ECS
    ecs: dict[str, Any] = {
        "@timestamp": ts or datetime.utcnow().isoformat() + "Z",
        "message": message.strip(),
        "raw": raw_str,
        "event": {
            "kind": "event",
            "severity": sev_ecs,
            "code": msg_id,
            "module": "cisco",
            "dataset": "cisco.asa",
            "provider": "ASA",
        },
        "log": {
            "level": sev_label,
            "syslog": {
                "severity": {"code": int(severity), "name": sev_label},
            },
        },
        "observer": {
            "hostname": hostname,
            "vendor": "Cisco",
            "product": "ASA",
            "type": "firewall",
        },
    }

    if hostname:
        ecs["host"] = {"name": hostname}

    # Route to specific parser
    parser_func = _MSG_ID_PARSERS.get(msg_id)
    if parser_func:
        specific = parser_func(msg_id, message)
        # Merge specific fields
        for key, value in specific.items():
            if key == "event":
                ecs["event"].update(value)
            elif isinstance(value, dict) and key in ecs and isinstance(ecs[key], dict):
                ecs[key].update(value)
            else:
                ecs[key] = value
    else:
        # Generic fallback — attempt to extract IPs
        extracted = _extract_ip_port_pairs(message)
        ecs["event"].update({
            "category": ["network"],
            "type": ["info"],
            "action": f"asa-{msg_id}",
        })
        if extracted.get("source"):
            ecs["source"] = extracted["source"]
        if extracted.get("destination"):
            ecs["destination"] = extracted["destination"]

    # ASA metadata
    ecs["cisco"] = {
        "asa": {
            "message_id": msg_id,
            "severity": severity,
            "severity_name": sev_label,
        },
    }

    # Related fields
    related_ips: list[str] = []
    src_ip = (ecs.get("source") or {}).get("ip")
    if src_ip:
        related_ips.append(src_ip)
    dst_ip = (ecs.get("destination") or {}).get("ip")
    if dst_ip:
        related_ips.append(dst_ip)
    related_users: list[str] = []
    user_name = (ecs.get("user") or {}).get("name")
    if user_name:
        related_users.append(user_name)
    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related:
        ecs["related"] = related

    ecs["cybernest"] = {
        "parser_name": "cisco_asa",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

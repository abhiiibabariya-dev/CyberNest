"""
CyberNest FortiGate Parser.

Parses FortiGate key=value syslog messages.
Handles log types: traffic, utm, event, voip.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.fortinet")

# FortiGate key=value pattern (handles quoted values)
FORTI_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

# FortiGate severity mapping
FORTI_SEVERITY: dict[str, int] = {
    "emergency": 100, "alert": 90, "critical": 80, "error": 70,
    "warning": 50, "notice": 40, "information": 20, "debug": 10,
}

# FortiGate log type to ECS category mapping
FORTI_TYPE_CATEGORIES: dict[str, list[str]] = {
    "traffic": ["network"],
    "utm": ["intrusion_detection", "network"],
    "event": ["host"],
    "voip": ["network"],
}

# UTM subtypes to ECS categories
UTM_SUBTYPE_CATEGORIES: dict[str, list[str]] = {
    "virus": ["malware"],
    "webfilter": ["web"],
    "ips": ["intrusion_detection"],
    "emailfilter": ["email"],
    "dlp": ["file"],
    "anomaly": ["intrusion_detection"],
    "voip": ["network"],
    "dns": ["network"],
    "waf": ["web"],
    "app-ctrl": ["network"],
    "icap": ["network"],
    "cifs": ["file"],
    "ssh": ["network"],
    "ssl": ["network"],
}


def _is_fortinet(raw_data: Any) -> bool:
    """Detect FortiGate syslog format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False

    # FortiGate logs contain specific key patterns
    return (
        ("logid=" in raw_str or "devid=" in raw_str or "devname=" in raw_str)
        and ("type=" in raw_str or "subtype=" in raw_str)
    )


def _parse_kv(raw_str: str) -> dict[str, str]:
    """Parse FortiGate key=value pairs."""
    result: dict[str, str] = {}
    for match in FORTI_KV_RE.finditer(raw_str):
        key = match.group(1)
        value = match.group(2)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        result[key] = value
    return result


def _safe_int(val: Optional[str]) -> Optional[int]:
    if not val or val == "N/A":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_forti_timestamp(date_str: Optional[str], time_str: Optional[str]) -> Optional[str]:
    """Parse FortiGate date and time fields."""
    if not date_str:
        return None
    ts_str = f"{date_str} {time_str}" if time_str else date_str
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
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


def _parse_traffic(kv: dict[str, str], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse FortiGate traffic log."""
    action = kv.get("action", "").lower()
    outcome = "success" if action in ("accept", "allow", "server-rst", "client-rst") else "failure"

    ecs["event"].update({
        "category": ["network"],
        "type": ["connection", "allowed" if outcome == "success" else "denied"],
        "action": action,
        "outcome": outcome,
        "duration": (_safe_int(kv.get("duration")) or 0) * 1_000_000_000,
    })

    ecs["source"] = {
        "ip": kv.get("srcip") or None,
        "port": _safe_int(kv.get("srcport")),
        "bytes": _safe_int(kv.get("sentbyte")),
        "packets": _safe_int(kv.get("sentpkt")),
        "mac": kv.get("srcmac") or None,
        "nat": {
            "ip": kv.get("transip") or kv.get("tranip") or None,
            "port": _safe_int(kv.get("transport") or kv.get("tranport")),
        },
    }
    ecs["destination"] = {
        "ip": kv.get("dstip") or None,
        "port": _safe_int(kv.get("dstport")),
        "bytes": _safe_int(kv.get("rcvdbyte")),
        "packets": _safe_int(kv.get("rcvdpkt")),
        "mac": kv.get("dstmac") or None,
        "nat": {
            "ip": kv.get("transdip") or None,
            "port": _safe_int(kv.get("transdport")),
        },
    }
    ecs["network"] = {
        "transport": kv.get("proto", "").lower() if kv.get("proto") else None,
        "application": kv.get("app") or kv.get("service") or None,
        "bytes": (_safe_int(kv.get("sentbyte")) or 0) + (_safe_int(kv.get("rcvdbyte")) or 0),
        "packets": (_safe_int(kv.get("sentpkt")) or 0) + (_safe_int(kv.get("rcvdpkt")) or 0),
        "direction": "inbound" if kv.get("dir", "") == "incoming" else "outbound" if kv.get("dir", "") == "outgoing" else None,
    }

    proto_num = kv.get("proto")
    if proto_num:
        proto_map = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
        ecs["network"]["transport"] = proto_map.get(proto_num, proto_num)

    ecs["rule"] = {
        "name": kv.get("policyname") or None,
        "id": kv.get("policyid") or None,
    }

    ecs["message"] = (
        f"FortiGate TRAFFIC: {kv.get('srcip', '')}:{kv.get('srcport', '')} -> "
        f"{kv.get('dstip', '')}:{kv.get('dstport', '')} {action} "
        f"({kv.get('app', kv.get('service', ''))})"
    )

    ecs["fortinet"] = {
        "log_type": "traffic",
        "subtype": kv.get("subtype"),
        "session_id": kv.get("sessionid"),
        "vd": kv.get("vd"),
        "srcintf": kv.get("srcintf"),
        "dstintf": kv.get("dstintf"),
        "poluuid": kv.get("poluuid"),
        "dstcountry": kv.get("dstcountry"),
        "srccountry": kv.get("srccountry"),
        "appcat": kv.get("appcat"),
        "crscore": _safe_int(kv.get("crscore")),
        "craction": _safe_int(kv.get("craction")),
        "crlevel": kv.get("crlevel"),
    }

    return ecs


def _parse_utm(kv: dict[str, str], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse FortiGate UTM log."""
    subtype = kv.get("subtype", "")
    action = kv.get("action", "").lower()
    outcome = "success" if action in ("passthrough", "pass", "allow", "detected") else "failure"

    categories = UTM_SUBTYPE_CATEGORIES.get(subtype, ["intrusion_detection", "network"])

    ecs["event"].update({
        "kind": "alert" if action in ("blocked", "dropped", "quarantine") else "event",
        "category": categories,
        "type": ["denied"] if outcome == "failure" else ["allowed"],
        "action": action,
        "outcome": outcome,
    })

    ecs["source"] = {
        "ip": kv.get("srcip") or None,
        "port": _safe_int(kv.get("srcport")),
    }
    ecs["destination"] = {
        "ip": kv.get("dstip") or None,
        "port": _safe_int(kv.get("dstport")),
    }
    ecs["network"] = {
        "transport": kv.get("proto", "").lower() if kv.get("proto") else None,
        "application": kv.get("app") or kv.get("service") or None,
    }
    ecs["rule"] = {
        "name": kv.get("policyname") or None,
        "id": kv.get("policyid") or None,
    }

    # UTM-specific fields
    msg = kv.get("msg", "")
    attack_name = kv.get("attack", "") or kv.get("virus", "")
    ecs["message"] = f"FortiGate UTM [{subtype}]: {attack_name or msg} ({action})"

    if subtype == "virus":
        ecs["file"] = {
            "name": kv.get("filename") or None,
            "hash": {"sha256": kv.get("checksumtype")} if kv.get("checksumtype") else None,
        }
        ecs["threat"] = {
            "indicator": {
                "type": "file",
                "description": kv.get("virus") or kv.get("analyticssubmit"),
                "provider": "fortiguard",
            },
        }
    elif subtype == "ips":
        ecs["rule"]["name"] = kv.get("attack") or kv.get("msg")
        ecs["rule"]["id"] = kv.get("attackid")
        ecs["rule"]["category"] = kv.get("attackcat") if kv.get("attackcat") else None
    elif subtype == "webfilter":
        ecs["url"] = {
            "original": kv.get("url") or None,
            "domain": kv.get("hostname") or None,
        }
        ecs["http"] = {
            "request": {
                "method": kv.get("reqtype") or None,
            },
        }
    elif subtype == "emailfilter":
        ecs["email"] = {
            "from": kv.get("from") or None,
            "to": [kv["to"]] if kv.get("to") else None,
            "subject": kv.get("subject") or None,
        }
    elif subtype == "dns":
        ecs["dns"] = {
            "question": {
                "name": kv.get("qname") or None,
                "type": kv.get("qtype") or None,
            },
        }
    elif subtype == "app-ctrl":
        ecs["network"]["application"] = kv.get("app") or kv.get("appcat")

    ecs["fortinet"] = {
        "log_type": "utm",
        "subtype": subtype,
        "session_id": kv.get("sessionid"),
        "vd": kv.get("vd"),
        "attack": kv.get("attack"),
        "attackid": kv.get("attackid"),
        "severity": kv.get("severity"),
        "ref": kv.get("ref"),
        "profile": kv.get("profile"),
        "crscore": _safe_int(kv.get("crscore")),
        "craction": _safe_int(kv.get("craction")),
    }

    return ecs


def _parse_event(kv: dict[str, str], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse FortiGate event log."""
    subtype = kv.get("subtype", "")
    action = kv.get("action", "").lower()

    # Map event subtypes
    if subtype in ("user", "vpn"):
        ecs["event"]["category"] = ["authentication"]
        outcome = "success" if action in ("login", "tunnel-up", "accept") else "failure"
        ecs["event"]["type"] = ["start"] if outcome == "success" else ["start"]
        ecs["event"]["outcome"] = outcome
        ecs["user"] = {
            "name": kv.get("user") or kv.get("srcuser") or None,
            "domain": kv.get("group") or None,
        }
    elif subtype == "system":
        ecs["event"]["category"] = ["host", "configuration"]
        ecs["event"]["type"] = ["change"]
        ecs["event"]["outcome"] = "success"
    elif subtype == "connector":
        ecs["event"]["category"] = ["configuration"]
        ecs["event"]["type"] = ["info"]
    else:
        ecs["event"]["category"] = ["host"]
        ecs["event"]["type"] = ["info"]

    ecs["event"]["action"] = action or subtype

    ecs["source"] = {
        "ip": kv.get("srcip") or kv.get("remip") or None,
        "port": _safe_int(kv.get("srcport") or kv.get("remport")),
    }
    ecs["destination"] = {
        "ip": kv.get("dstip") or kv.get("locip") or None,
        "port": _safe_int(kv.get("dstport") or kv.get("locport")),
    }

    msg = kv.get("msg", "")
    ecs["message"] = f"FortiGate EVENT [{subtype}]: {msg} ({action})"

    ecs["fortinet"] = {
        "log_type": "event",
        "subtype": subtype,
        "vd": kv.get("vd"),
        "logdesc": kv.get("logdesc"),
        "msg": msg,
        "status": kv.get("status"),
        "reason": kv.get("reason"),
        "tunneltype": kv.get("tunneltype"),
        "tunnelid": kv.get("tunnelid"),
    }

    return ecs


def _parse_voip(kv: dict[str, str], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse FortiGate VoIP log."""
    ecs["event"].update({
        "category": ["network"],
        "type": ["protocol"],
        "action": kv.get("action", "voip"),
    })

    ecs["source"] = {
        "ip": kv.get("srcip") or None,
        "port": _safe_int(kv.get("srcport")),
    }
    ecs["destination"] = {
        "ip": kv.get("dstip") or None,
        "port": _safe_int(kv.get("dstport")),
    }
    ecs["network"] = {
        "protocol": "sip",
        "application": kv.get("voipproto") or "sip",
    }

    msg = kv.get("msg", "")
    ecs["message"] = f"FortiGate VOIP: {msg}"

    ecs["fortinet"] = {
        "log_type": "voip",
        "subtype": kv.get("subtype"),
        "vd": kv.get("vd"),
        "voipproto": kv.get("voipproto"),
        "msg": msg,
    }

    return ecs


_LOG_TYPE_PARSERS = {
    "traffic": _parse_traffic,
    "utm": _parse_utm,
    "event": _parse_event,
    "voip": _parse_voip,
}


@register_parser("fortinet", detector=_is_fortinet, priority=23)
def parse_fortinet(raw_data: Any) -> dict[str, Any]:
    """Parse a FortiGate syslog to ECS format."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    kv = _parse_kv(raw_str)
    if not kv:
        raise ValueError(f"No key=value pairs found in FortiGate log: {raw_str[:100]}")

    log_type = kv.get("type", "").lower()
    ts = _parse_forti_timestamp(kv.get("date"), kv.get("time"))
    level = kv.get("level", "notice").lower()
    severity = FORTI_SEVERITY.get(level, 40)

    ecs: dict[str, Any] = {
        "@timestamp": ts or datetime.utcnow().isoformat() + "Z",
        "raw": raw_str,
        "event": {
            "kind": "event",
            "severity": severity,
            "module": "fortinet",
            "dataset": f"fortinet.{log_type}",
            "provider": "fortigate",
            "code": kv.get("logid"),
        },
        "observer": {
            "hostname": kv.get("devname") or None,
            "serial_number": kv.get("devid") or None,
            "vendor": "Fortinet",
            "product": "FortiGate",
            "type": "firewall",
        },
        "host": {
            "name": kv.get("devname") or None,
        },
    }

    parser_func = _LOG_TYPE_PARSERS.get(log_type)
    if parser_func:
        ecs = parser_func(kv, ecs)
    else:
        ecs["event"].update({
            "category": ["host"],
            "type": ["info"],
            "action": kv.get("action", log_type),
        })
        ecs["message"] = f"FortiGate [{log_type}]: {kv.get('msg', '')}"
        ecs["fortinet"] = {"log_type": log_type, "raw_kv": kv}

    # Related fields
    related_ips: list[str] = []
    for key in ("srcip", "dstip", "remip", "locip", "transip", "transdip"):
        ip = kv.get(key)
        if ip and ip not in ("0.0.0.0", "N/A", ""):
            related_ips.append(ip)
    related_users: list[str] = []
    for key in ("user", "srcuser", "dstuser"):
        u = kv.get(key)
        if u and u not in ("N/A", ""):
            related_users.append(u)
    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related:
        ecs["related"] = related

    ecs["cybernest"] = {
        "parser_name": "fortinet",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

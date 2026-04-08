"""
CyberNest Suricata EVE JSON Parser.

Parses Suricata EVE JSON log output and maps to ECS fields.
Handles event_types: alert, dns, http, flow, tls, smtp, ssh.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.suricata_eve")


def _is_suricata_eve(raw_data: Any) -> bool:
    """Detect Suricata EVE JSON format."""
    if isinstance(raw_data, dict):
        data = raw_data
    elif isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            return False
    else:
        return False

    # Suricata EVE always has event_type and usually has src_ip/dest_ip
    return "event_type" in data and ("src_ip" in data or "flow_id" in data)


def _safe_int(val: Any) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_timestamp(ts: Any) -> Optional[str]:
    if ts is None:
        return None
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat() + "Z"
        except (ValueError, TypeError):
            return ts
    return str(ts)


def _build_base_ecs(data: dict[str, Any]) -> dict[str, Any]:
    """Build common ECS fields from Suricata base fields."""
    ts = _parse_timestamp(data.get("timestamp"))

    ecs: dict[str, Any] = {
        "@timestamp": ts or datetime.utcnow().isoformat() + "Z",
        "raw": json.dumps(data, default=str),
        "event": {
            "kind": "event",
            "module": "suricata",
            "dataset": f"suricata.{data.get('event_type', 'unknown')}",
        },
        "source": {
            "ip": data.get("src_ip"),
            "port": _safe_int(data.get("src_port")),
        },
        "destination": {
            "ip": data.get("dest_ip"),
            "port": _safe_int(data.get("dest_port")),
        },
        "network": {
            "transport": data.get("proto", "").lower() if data.get("proto") else None,
            "community_id": data.get("community_id"),
        },
    }

    # Collect related IPs
    related_ips = []
    if data.get("src_ip"):
        related_ips.append(data["src_ip"])
    if data.get("dest_ip"):
        related_ips.append(data["dest_ip"])
    if related_ips:
        ecs["related"] = {"ip": list(set(related_ips))}

    if data.get("in_iface"):
        ecs.setdefault("observer", {})["ingress"] = {"interface": {"name": data["in_iface"]}}

    if data.get("flow_id"):
        ecs["suricata"] = {"flow_id": data["flow_id"]}

    return ecs


def _parse_alert(data: dict[str, Any], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse Suricata alert event_type."""
    alert = data.get("alert", {})

    ecs["event"].update({
        "kind": "alert",
        "category": ["intrusion_detection", "network"],
        "type": ["denied"] if alert.get("action") == "blocked" else ["allowed"],
        "action": alert.get("action", "allowed"),
        "severity": alert.get("severity", 3) * 25,
    })

    ecs["rule"] = {
        "id": str(alert.get("signature_id", "")),
        "name": alert.get("signature", ""),
        "category": alert.get("category", ""),
        "description": alert.get("signature", ""),
        "version": str(alert.get("rev", "")),
        "ruleset": alert.get("gid", ""),
    }

    ecs["message"] = f"[{alert.get('severity', 3)}:{alert.get('signature_id', '')}] {alert.get('signature', '')}"

    # Map alert metadata
    metadata = alert.get("metadata", {})
    if metadata:
        mitre_ids = metadata.get("mitre_technique_id", [])
        mitre_tactics = metadata.get("mitre_tactic_id", [])
        if mitre_ids or mitre_tactics:
            ecs["threat"] = {
                "framework": "MITRE ATT&CK",
            }
            if mitre_tactics:
                ecs["threat"]["tactic"] = {"id": mitre_tactics[0] if isinstance(mitre_tactics, list) else str(mitre_tactics)}
            if mitre_ids:
                ecs["threat"]["technique"] = [{"id": tid} for tid in (mitre_ids if isinstance(mitre_ids, list) else [mitre_ids])]

    # Packet payload
    if data.get("payload"):
        ecs["suricata"]["payload"] = data["payload"]
    if data.get("payload_printable"):
        ecs["suricata"]["payload_printable"] = data["payload_printable"]

    return ecs


def _parse_dns(data: dict[str, Any], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse Suricata DNS event_type."""
    dns_data = data.get("dns", {})

    ecs["event"].update({
        "category": ["network"],
        "type": ["protocol"],
        "action": "dns-query" if dns_data.get("type") == "query" else "dns-answer",
    })

    dns_ecs: dict[str, Any] = {
        "type": dns_data.get("type"),
        "id": str(dns_data.get("id", "")),
    }

    if dns_data.get("type") == "query":
        dns_ecs["question"] = {
            "name": dns_data.get("rrname"),
            "type": dns_data.get("rrtype"),
        }
        ecs["message"] = f"DNS query: {dns_data.get('rrname', '')} ({dns_data.get('rrtype', '')})"
    else:
        # Answer
        answers = dns_data.get("answers", [])
        if answers:
            dns_ecs["answers"] = [
                {
                    "name": a.get("rrname"),
                    "type": a.get("rrtype"),
                    "data": a.get("rdata"),
                    "ttl": a.get("ttl"),
                }
                for a in answers
            ]
            resolved = [a.get("rdata") for a in answers if a.get("rdata")]
            if resolved:
                dns_ecs["resolved_ip"] = resolved
        elif dns_data.get("rrname"):
            dns_ecs["question"] = {
                "name": dns_data.get("rrname"),
                "type": dns_data.get("rrtype"),
            }
            if dns_data.get("rdata"):
                dns_ecs["answers"] = [{
                    "name": dns_data.get("rrname"),
                    "type": dns_data.get("rrtype"),
                    "data": dns_data.get("rdata"),
                    "ttl": dns_data.get("ttl"),
                }]

        ecs["message"] = f"DNS answer: {dns_data.get('rrname', '')} -> {dns_data.get('rdata', '')}"

    ecs["dns"] = dns_ecs
    ecs["network"]["protocol"] = "dns"

    # Add queried domain to related
    if dns_data.get("rrname"):
        ecs.setdefault("related", {}).setdefault("hosts", []).append(dns_data["rrname"])

    return ecs


def _parse_http(data: dict[str, Any], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse Suricata HTTP event_type."""
    http = data.get("http", {})

    ecs["event"].update({
        "category": ["web", "network"],
        "type": ["protocol", "access"],
        "action": "http-request",
    })

    ecs["http"] = {
        "request": {
            "method": http.get("http_method"),
            "bytes": _safe_int(http.get("length")),
            "referrer": http.get("http_refer"),
        },
        "response": {
            "status_code": _safe_int(http.get("status")),
            "bytes": _safe_int(http.get("response_body_len")),
        },
        "version": http.get("protocol"),
    }

    ecs["url"] = {
        "original": http.get("url"),
        "domain": http.get("hostname"),
        "path": http.get("url"),
    }

    if http.get("http_user_agent"):
        ecs["user_agent"] = {"original": http["http_user_agent"]}

    if http.get("http_content_type"):
        ecs["http"]["response"]["mime_type"] = http["http_content_type"]

    ecs["message"] = f"HTTP {http.get('http_method', '')} {http.get('hostname', '')}{http.get('url', '')} -> {http.get('status', '')}"
    ecs["network"]["protocol"] = "http"

    if http.get("hostname"):
        ecs.setdefault("related", {}).setdefault("hosts", []).append(http["hostname"])

    return ecs


def _parse_flow(data: dict[str, Any], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse Suricata flow event_type."""
    flow = data.get("flow", {})

    ecs["event"].update({
        "category": ["network"],
        "type": ["connection", "end"],
        "action": "flow-end",
        "duration": _safe_int(flow.get("age")) * 1_000_000_000 if flow.get("age") else None,
        "start": _parse_timestamp(flow.get("start")),
        "end": _parse_timestamp(flow.get("end")),
    })

    ecs["source"]["bytes"] = _safe_int(flow.get("bytes_toserver"))
    ecs["source"]["packets"] = _safe_int(flow.get("pkts_toserver"))
    ecs["destination"]["bytes"] = _safe_int(flow.get("bytes_toclient"))
    ecs["destination"]["packets"] = _safe_int(flow.get("pkts_toclient"))

    total_bytes = (_safe_int(flow.get("bytes_toserver")) or 0) + (_safe_int(flow.get("bytes_toclient")) or 0)
    total_packets = (_safe_int(flow.get("pkts_toserver")) or 0) + (_safe_int(flow.get("pkts_toclient")) or 0)
    ecs["network"]["bytes"] = total_bytes
    ecs["network"]["packets"] = total_packets

    if flow.get("state"):
        ecs.setdefault("suricata", {})["flow_state"] = flow["state"]
    if flow.get("reason"):
        ecs.setdefault("suricata", {})["flow_reason"] = flow["reason"]

    ecs["message"] = (
        f"Flow: {data.get('src_ip', '')}:{data.get('src_port', '')} -> "
        f"{data.get('dest_ip', '')}:{data.get('dest_port', '')} "
        f"({total_bytes} bytes, {total_packets} packets)"
    )

    return ecs


def _parse_tls(data: dict[str, Any], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse Suricata TLS event_type."""
    tls = data.get("tls", {})

    ecs["event"].update({
        "category": ["network"],
        "type": ["protocol", "connection"],
        "action": "tls-negotiated",
    })

    ecs["tls"] = {
        "version": tls.get("version"),
        "version_protocol": "tls",
        "server": {
            "subject": tls.get("subject"),
            "issuer": tls.get("issuerdn"),
            "not_before": tls.get("notbefore"),
            "not_after": tls.get("notafter"),
            "ja3s": tls.get("ja3s", {}).get("hash") if isinstance(tls.get("ja3s"), dict) else tls.get("ja3s"),
        },
        "client": {
            "ja3": tls.get("ja3", {}).get("hash") if isinstance(tls.get("ja3"), dict) else tls.get("ja3"),
        },
    }

    if tls.get("sni"):
        ecs["destination"]["domain"] = tls["sni"]
        ecs.setdefault("related", {}).setdefault("hosts", []).append(tls["sni"])

    if tls.get("fingerprint"):
        ecs["tls"]["server"]["hash"] = {"sha1": tls["fingerprint"]}

    if tls.get("serial"):
        ecs["tls"]["server"]["x509"] = {"serial_number": tls["serial"]}

    ecs["message"] = f"TLS {tls.get('version', '')} to {tls.get('sni', data.get('dest_ip', ''))}"
    ecs["network"]["protocol"] = "tls"

    return ecs


def _parse_smtp(data: dict[str, Any], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse Suricata SMTP event_type."""
    smtp = data.get("smtp", {})
    email = data.get("email", {})

    ecs["event"].update({
        "category": ["email", "network"],
        "type": ["protocol"],
        "action": "smtp-message",
    })

    ecs["email"] = {
        "from": email.get("from") or smtp.get("mail_from"),
        "to": email.get("to", []) if isinstance(email.get("to"), list) else [email["to"]] if email.get("to") else [],
        "subject": email.get("subject"),
        "message_id": email.get("message-id"),
    }

    if smtp.get("helo"):
        ecs.setdefault("suricata", {})["smtp_helo"] = smtp["helo"]
    if smtp.get("rcpt_to"):
        ecs["email"]["to"] = smtp["rcpt_to"] if isinstance(smtp["rcpt_to"], list) else [smtp["rcpt_to"]]

    sender = email.get("from") or smtp.get("mail_from", "")
    ecs["message"] = f"SMTP from {sender} to {email.get('to', smtp.get('rcpt_to', ''))}: {email.get('subject', '')}"
    ecs["network"]["protocol"] = "smtp"

    return ecs


def _parse_ssh(data: dict[str, Any], ecs: dict[str, Any]) -> dict[str, Any]:
    """Parse Suricata SSH event_type."""
    ssh = data.get("ssh", {})

    ecs["event"].update({
        "category": ["authentication", "network"],
        "type": ["protocol", "connection"],
        "action": "ssh-connection",
    })

    client = ssh.get("client", {})
    server = ssh.get("server", {})

    ecs["ssh"] = {
        "client": {
            "software_version": client.get("software_version"),
            "proto_version": client.get("proto_version"),
        },
        "server": {
            "software_version": server.get("software_version"),
            "proto_version": server.get("proto_version"),
        },
    }

    ecs["message"] = (
        f"SSH {client.get('proto_version', '')} "
        f"{client.get('software_version', '')} -> "
        f"{server.get('software_version', '')}"
    )
    ecs["network"]["protocol"] = "ssh"

    return ecs


# Dispatcher
_EVENT_TYPE_PARSERS = {
    "alert": _parse_alert,
    "dns": _parse_dns,
    "http": _parse_http,
    "flow": _parse_flow,
    "tls": _parse_tls,
    "smtp": _parse_smtp,
    "ssh": _parse_ssh,
}


@register_parser("suricata_eve", detector=_is_suricata_eve, priority=12)
def parse_suricata_eve(raw_data: Any) -> dict[str, Any]:
    """Parse a Suricata EVE JSON event to ECS format."""
    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid Suricata EVE JSON: {exc}") from exc
    elif isinstance(raw_data, dict):
        data = raw_data
    else:
        raise ValueError(f"Unsupported data type for Suricata EVE: {type(raw_data)}")

    ecs = _build_base_ecs(data)

    event_type = data.get("event_type", "")
    parser_func = _EVENT_TYPE_PARSERS.get(event_type)

    if parser_func:
        ecs = parser_func(data, ecs)
    else:
        # Generic event type
        ecs["event"].update({
            "category": ["network"],
            "type": ["info"],
            "action": f"suricata-{event_type}",
        })
        ecs["message"] = f"Suricata {event_type} event"
        ecs.setdefault("suricata", {})["raw_event"] = data

    ecs["cybernest"] = {
        "parser_name": "suricata_eve",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

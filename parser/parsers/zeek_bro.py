"""
CyberNest Zeek (Bro) Log Parser.

Parses Zeek TSV and JSON log formats.
Handles log types: conn, dns, http, ssl, files, weird, notice.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.zeek")

# Zeek TSV separator tag
ZEEK_SEPARATOR_RE = re.compile(r"^#separator\s+(.*)$")
ZEEK_FIELDS_RE = re.compile(r"^#fields\s+(.*)$")
ZEEK_TYPES_RE = re.compile(r"^#types\s+(.*)$")

# Zeek TSV default fields per log type
CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]

DNS_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
    "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
    "RA", "Z", "answers", "TTLs", "rejected",
]

HTTP_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "trans_depth", "method", "host", "uri", "referrer", "version",
    "user_agent", "origin", "request_body_len", "response_body_len",
    "status_code", "status_msg", "info_code", "info_msg", "tags",
    "username", "password", "proxied", "orig_fuids", "orig_filenames",
    "orig_mime_types", "resp_fuids", "resp_filenames", "resp_mime_types",
]

SSL_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "version", "cipher", "curve", "server_name", "resumed", "last_alert",
    "next_protocol", "established", "cert_chain_fuids", "client_cert_chain_fuids",
    "subject", "issuer", "client_subject", "client_issuer", "validation_status",
]

FILES_FIELDS = [
    "ts", "fuid", "tx_hosts", "rx_hosts", "conn_uids", "source", "depth",
    "analyzers", "mime_type", "filename", "duration", "local_orig",
    "is_orig", "seen_bytes", "total_bytes", "missing_bytes", "overflow_bytes",
    "timedout", "parent_fuid", "md5", "sha1", "sha256", "extracted",
    "extracted_cutoff", "extracted_size",
]

WEIRD_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "name", "addl", "notice", "peer", "source",
]

NOTICE_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "fuid", "file_mime_type", "file_desc", "proto", "note", "msg",
    "sub", "src", "dst", "p", "n", "peer_descr", "actions",
    "suppress_for", "remote_location.country_code", "remote_location.region",
    "remote_location.city", "remote_location.latitude", "remote_location.longitude",
]


def _is_zeek(raw_data: Any) -> bool:
    """Detect Zeek log format (TSV or JSON)."""
    if isinstance(raw_data, dict):
        # Zeek JSON has 'id.orig_h' or '_path' or 'uid' fields
        return "id.orig_h" in raw_data or "_path" in raw_data or (
            "uid" in raw_data and "ts" in raw_data and not "event_type" in raw_data
        )
    if isinstance(raw_data, str):
        stripped = raw_data.strip()
        # Zeek TSV header
        if stripped.startswith("#separator") or stripped.startswith("#fields"):
            return True
        # Zeek JSON
        if stripped.startswith("{"):
            try:
                d = json.loads(stripped)
                return "id.orig_h" in d or "_path" in d
            except (json.JSONDecodeError, TypeError):
                return False
        # Tab-separated with Zeek-like epoch timestamp
        parts = stripped.split("\t")
        if len(parts) >= 8:
            try:
                ts = float(parts[0])
                return 1_000_000_000 < ts < 2_000_000_000
            except (ValueError, TypeError):
                return False
    return False


def _safe_int(val: Any) -> Optional[int]:
    if val is None or val == "-" or val == "(empty)":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _safe_float(val: Any) -> Optional[float]:
    if val is None or val == "-" or val == "(empty)":
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def _zeek_ts(val: Any) -> Optional[str]:
    """Convert Zeek epoch timestamp to ISO format."""
    if val is None or val == "-":
        return None
    try:
        epoch = float(val)
        return datetime.utcfromtimestamp(epoch).isoformat() + "Z"
    except (ValueError, TypeError, OSError):
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00")).isoformat() + "Z"
            except (ValueError, TypeError):
                pass
        return str(val)


def _zeek_list(val: Any) -> list[str]:
    """Parse Zeek set/vector field (comma-separated)."""
    if val is None or val == "-" or val == "(empty)":
        return []
    if isinstance(val, list):
        return val
    return [x.strip() for x in str(val).split(",") if x.strip() and x.strip() != "-"]


def _parse_zeek_tsv_line(line: str, fields: list[str]) -> dict[str, str]:
    """Parse a Zeek TSV line using field names."""
    values = line.split("\t")
    result: dict[str, str] = {}
    for i, field in enumerate(fields):
        result[field] = values[i] if i < len(values) else "-"
    return result


def _detect_log_type(data: dict[str, Any]) -> str:
    """Detect Zeek log type from data fields."""
    if "_path" in data:
        return data["_path"]
    if "conn_state" in data or "history" in data:
        return "conn"
    if "query" in data and ("qtype" in data or "qtype_name" in data):
        return "dns"
    if "method" in data and "uri" in data and "status_code" in data:
        return "http"
    if "cipher" in data or "server_name" in data:
        return "ssl"
    if "mime_type" in data and "seen_bytes" in data:
        return "files"
    if "note" in data and "msg" in data and "actions" in data:
        return "notice"
    if "name" in data and "addl" in data:
        return "weird"
    return "unknown"


def _parse_conn(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Zeek conn.log."""
    duration = _safe_float(data.get("duration"))
    return {
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "network-connection",
            "duration": int(duration * 1_000_000_000) if duration else None,
            "module": "zeek",
            "dataset": "zeek.conn",
        },
        "message": (
            f"Connection: {data.get('id.orig_h', '')}:{data.get('id.orig_p', '')} -> "
            f"{data.get('id.resp_h', '')}:{data.get('id.resp_p', '')} "
            f"({data.get('proto', '')})"
        ),
        "network": {
            "transport": data.get("proto", "").lower() if data.get("proto") else None,
            "application": data.get("service"),
            "bytes": (_safe_int(data.get("orig_bytes")) or 0) + (_safe_int(data.get("resp_bytes")) or 0),
            "packets": (_safe_int(data.get("orig_pkts")) or 0) + (_safe_int(data.get("resp_pkts")) or 0),
            "community_id": data.get("community_id"),
        },
        "source": {
            "bytes": _safe_int(data.get("orig_bytes")),
            "packets": _safe_int(data.get("orig_pkts")),
        },
        "destination": {
            "bytes": _safe_int(data.get("resp_bytes")),
            "packets": _safe_int(data.get("resp_pkts")),
        },
        "zeek": {
            "conn_state": data.get("conn_state"),
            "history": data.get("history"),
            "missed_bytes": _safe_int(data.get("missed_bytes")),
            "local_orig": data.get("local_orig"),
            "local_resp": data.get("local_resp"),
            "tunnel_parents": _zeek_list(data.get("tunnel_parents")),
        },
    }


def _parse_dns(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Zeek dns.log."""
    answers = _zeek_list(data.get("answers"))
    return {
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["protocol"],
            "action": "dns-query",
            "module": "zeek",
            "dataset": "zeek.dns",
        },
        "message": f"DNS: {data.get('query', '')} ({data.get('qtype_name', '')}) -> {', '.join(answers) if answers else data.get('rcode_name', '')}",
        "dns": {
            "question": {
                "name": data.get("query"),
                "type": data.get("qtype_name"),
                "class": data.get("qclass_name"),
            },
            "response_code": data.get("rcode_name"),
            "id": data.get("trans_id"),
            "answers": [{"data": a} for a in answers] if answers else None,
            "resolved_ip": [a for a in answers if re.match(r"\d+\.\d+\.\d+\.\d+", a)] if answers else None,
        },
        "network": {
            "transport": data.get("proto", "").lower() if data.get("proto") else None,
            "protocol": "dns",
        },
        "zeek": {
            "rtt": _safe_float(data.get("rtt")),
            "AA": data.get("AA"),
            "TC": data.get("TC"),
            "RD": data.get("RD"),
            "RA": data.get("RA"),
            "rejected": data.get("rejected"),
        },
    }


def _parse_http(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Zeek http.log."""
    return {
        "event": {
            "kind": "event",
            "category": ["web", "network"],
            "type": ["protocol", "access"],
            "action": "http-request",
            "module": "zeek",
            "dataset": "zeek.http",
        },
        "message": f"HTTP {data.get('method', '')} {data.get('host', '')}{data.get('uri', '')} -> {data.get('status_code', '')}",
        "http": {
            "version": data.get("version"),
            "request": {
                "method": data.get("method"),
                "bytes": _safe_int(data.get("request_body_len")),
                "referrer": data.get("referrer") if data.get("referrer") != "-" else None,
            },
            "response": {
                "status_code": _safe_int(data.get("status_code")),
                "bytes": _safe_int(data.get("response_body_len")),
            },
        },
        "url": {
            "domain": data.get("host"),
            "path": data.get("uri"),
            "original": f"{data.get('host', '')}{data.get('uri', '')}",
        },
        "user_agent": {
            "original": data.get("user_agent") if data.get("user_agent") != "-" else None,
        },
        "user": {
            "name": data.get("username") if data.get("username") != "-" else None,
        },
        "network": {"protocol": "http"},
        "zeek": {
            "trans_depth": _safe_int(data.get("trans_depth")),
            "status_msg": data.get("status_msg"),
            "tags": _zeek_list(data.get("tags")),
            "resp_mime_types": _zeek_list(data.get("resp_mime_types")),
            "orig_mime_types": _zeek_list(data.get("orig_mime_types")),
        },
    }


def _parse_ssl(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Zeek ssl.log."""
    return {
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["protocol", "connection"],
            "action": "tls-connection",
            "module": "zeek",
            "dataset": "zeek.ssl",
        },
        "message": f"TLS {data.get('version', '')} to {data.get('server_name', data.get('id.resp_h', ''))}",
        "tls": {
            "version": data.get("version"),
            "cipher": data.get("cipher"),
            "curve": data.get("curve"),
            "server": {
                "subject": data.get("subject"),
                "issuer": data.get("issuer"),
            },
            "client": {
                "subject": data.get("client_subject"),
                "issuer": data.get("client_issuer"),
            },
            "established": data.get("established") == "T" if data.get("established") else None,
            "resumed": data.get("resumed") == "T" if data.get("resumed") else None,
        },
        "destination": {
            "domain": data.get("server_name"),
        },
        "network": {"protocol": "tls"},
        "zeek": {
            "last_alert": data.get("last_alert"),
            "next_protocol": data.get("next_protocol"),
            "validation_status": data.get("validation_status"),
            "cert_chain_fuids": _zeek_list(data.get("cert_chain_fuids")),
        },
    }


def _parse_files(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Zeek files.log."""
    hashes: dict[str, str] = {}
    related_hashes: list[str] = []
    for algo in ("md5", "sha1", "sha256"):
        val = data.get(algo)
        if val and val != "-":
            hashes[algo] = val
            related_hashes.append(val)

    return {
        "event": {
            "kind": "event",
            "category": ["file"],
            "type": ["info"],
            "action": "file-transfer",
            "module": "zeek",
            "dataset": "zeek.files",
        },
        "message": f"File: {data.get('filename', data.get('fuid', ''))} ({data.get('mime_type', '')})",
        "file": {
            "name": data.get("filename") if data.get("filename") != "-" else None,
            "size": _safe_int(data.get("total_bytes")),
            "mime_type": data.get("mime_type") if data.get("mime_type") != "-" else None,
            "hash": hashes if hashes else None,
        },
        "related": {
            "hash": related_hashes if related_hashes else None,
        },
        "zeek": {
            "fuid": data.get("fuid"),
            "source": data.get("source"),
            "depth": _safe_int(data.get("depth")),
            "analyzers": _zeek_list(data.get("analyzers")),
            "seen_bytes": _safe_int(data.get("seen_bytes")),
            "missing_bytes": _safe_int(data.get("missing_bytes")),
            "overflow_bytes": _safe_int(data.get("overflow_bytes")),
            "timedout": data.get("timedout"),
            "is_orig": data.get("is_orig"),
            "conn_uids": _zeek_list(data.get("conn_uids")),
            "tx_hosts": _zeek_list(data.get("tx_hosts")),
            "rx_hosts": _zeek_list(data.get("rx_hosts")),
            "extracted": data.get("extracted") if data.get("extracted") != "-" else None,
        },
    }


def _parse_weird(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Zeek weird.log."""
    return {
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["info"],
            "action": f"zeek-weird-{data.get('name', 'unknown')}",
            "module": "zeek",
            "dataset": "zeek.weird",
        },
        "message": f"Weird: {data.get('name', '')} - {data.get('addl', '')}",
        "zeek": {
            "weird_name": data.get("name"),
            "weird_addl": data.get("addl"),
            "notice": data.get("notice"),
            "peer": data.get("peer"),
        },
    }


def _parse_notice(data: dict[str, Any]) -> dict[str, Any]:
    """Parse Zeek notice.log."""
    return {
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "network"],
            "type": ["info"],
            "action": data.get("note", "zeek-notice"),
            "module": "zeek",
            "dataset": "zeek.notice",
        },
        "message": f"Notice [{data.get('note', '')}]: {data.get('msg', '')}",
        "rule": {
            "name": data.get("note"),
            "description": data.get("msg"),
        },
        "zeek": {
            "note": data.get("note"),
            "msg": data.get("msg"),
            "sub": data.get("sub"),
            "src": data.get("src"),
            "dst": data.get("dst"),
            "p": _safe_int(data.get("p")),
            "n": _safe_int(data.get("n")),
            "actions": _zeek_list(data.get("actions")),
            "suppress_for": _safe_float(data.get("suppress_for")),
            "peer_descr": data.get("peer_descr"),
            "fuid": data.get("fuid"),
            "file_mime_type": data.get("file_mime_type"),
        },
    }


_LOG_TYPE_PARSERS = {
    "conn": _parse_conn,
    "dns": _parse_dns,
    "http": _parse_http,
    "ssl": _parse_ssl,
    "files": _parse_files,
    "weird": _parse_weird,
    "notice": _parse_notice,
}


@register_parser("zeek", detector=_is_zeek, priority=18)
def parse_zeek(raw_data: Any) -> dict[str, Any]:
    """Parse a Zeek log entry (TSV or JSON) to ECS format."""
    # Convert to dict
    if isinstance(raw_data, str):
        stripped = raw_data.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid Zeek JSON: {exc}") from exc
        elif stripped.startswith("#"):
            raise ValueError("Zeek TSV header lines should be skipped")
        else:
            # Try TSV parsing - auto-detect based on field count
            parts = stripped.split("\t")
            if len(parts) >= 20:
                data = _parse_zeek_tsv_line(stripped, CONN_FIELDS)
            elif len(parts) >= 15:
                data = _parse_zeek_tsv_line(stripped, DNS_FIELDS[:len(parts)])
            else:
                data = _parse_zeek_tsv_line(stripped, CONN_FIELDS[:len(parts)])
    elif isinstance(raw_data, dict):
        data = raw_data
    else:
        raise ValueError(f"Unsupported Zeek data type: {type(raw_data)}")

    raw_str = json.dumps(data, default=str) if isinstance(raw_data, dict) else str(raw_data)

    # Detect log type and parse
    log_type = _detect_log_type(data)
    parser_func = _LOG_TYPE_PARSERS.get(log_type)

    if parser_func:
        ecs = parser_func(data)
    else:
        ecs = {
            "event": {
                "kind": "event",
                "category": ["network"],
                "type": ["info"],
                "action": f"zeek-{log_type}",
                "module": "zeek",
                "dataset": f"zeek.{log_type}",
            },
            "message": f"Zeek {log_type} log entry",
            "zeek": data,
        }

    # Set common fields
    ts = _zeek_ts(data.get("ts"))
    if ts:
        ecs["@timestamp"] = ts
    else:
        ecs["@timestamp"] = datetime.utcnow().isoformat() + "Z"

    ecs["raw"] = raw_str

    # Set source/destination from id fields
    if data.get("id.orig_h"):
        ecs.setdefault("source", {})["ip"] = data["id.orig_h"]
    if data.get("id.orig_p"):
        ecs.setdefault("source", {})["port"] = _safe_int(data["id.orig_p"])
    if data.get("id.resp_h"):
        ecs.setdefault("destination", {})["ip"] = data["id.resp_h"]
    if data.get("id.resp_p"):
        ecs.setdefault("destination", {})["port"] = _safe_int(data["id.resp_p"])

    # Zeek UID
    if data.get("uid"):
        ecs.setdefault("zeek", {})["session_id"] = data["uid"]

    # Related IPs
    related_ips = []
    if data.get("id.orig_h") and data["id.orig_h"] != "-":
        related_ips.append(data["id.orig_h"])
    if data.get("id.resp_h") and data["id.resp_h"] != "-":
        related_ips.append(data["id.resp_h"])
    if data.get("src") and data["src"] != "-":
        related_ips.append(data["src"])
    if data.get("dst") and data["dst"] != "-":
        related_ips.append(data["dst"])
    if related_ips:
        ecs.setdefault("related", {})["ip"] = list(set(related_ips))

    # Related hosts
    related_hosts = []
    if data.get("host") and data["host"] != "-":
        related_hosts.append(data["host"])
    if data.get("server_name") and data["server_name"] != "-":
        related_hosts.append(data["server_name"])
    if data.get("query") and data["query"] != "-":
        related_hosts.append(data["query"])
    if related_hosts:
        ecs.setdefault("related", {}).setdefault("hosts", []).extend(related_hosts)
        ecs["related"]["hosts"] = list(set(ecs["related"]["hosts"]))

    ecs["cybernest"] = {
        "parser_name": "zeek",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

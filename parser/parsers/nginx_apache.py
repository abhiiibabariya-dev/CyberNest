"""
CyberNest Nginx/Apache Combined Log Format Parser.

Parses the standard combined log format used by both Nginx and Apache:
  client_ip - user [timestamp] "method url protocol" status size "referrer" "user_agent"
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.nginx_apache")

# Combined log format regex
COMBINED_RE = re.compile(
    r'^(\S+)\s+'           # client IP
    r'(\S+)\s+'            # ident (usually -)
    r'(\S+)\s+'            # auth user (usually -)
    r'\[([^\]]+)\]\s+'     # timestamp
    r'"(\S+)\s+'           # method
    r'(\S+)\s+'            # URL
    r'(\S+)"\s+'           # protocol
    r'(\d{3})\s+'          # status code
    r'(\S+)'               # response size
    r'(?:\s+"([^"]*)")?'   # referrer (optional)
    r'(?:\s+"([^"]*)")?'   # user agent (optional)
    r'(?:\s+"([^"]*)")?'   # X-Forwarded-For (optional)
    r'(.*)$'               # remainder
)

# Alternate pattern for logs without quotes around request
SIMPLE_RE = re.compile(
    r'^(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'\[([^\]]+)\]\s+'
    r'"([^"]+)"\s+'
    r'(\d{3})\s+'
    r'(\S+)'
    r'(?:\s+"([^"]*)")?'
    r'(?:\s+"([^"]*)")?'
    r'(.*)$'
)


def _is_nginx_apache(raw_data: Any) -> bool:
    """Detect Nginx/Apache combined log format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False

    if not raw_str:
        return False

    # Check for combined log pattern: IP - - [timestamp] "METHOD
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[', raw_str))


def _parse_clf_timestamp(ts_str: str) -> Optional[str]:
    """Parse CLF timestamp: dd/Mon/YYYY:HH:MM:SS +ZZZZ."""
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except ValueError:
        try:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
            return dt.isoformat() + "Z"
        except ValueError:
            return ts_str


def _safe_int(val: Optional[str]) -> Optional[int]:
    if val is None or val == "-":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_url(url_str: str) -> dict[str, Any]:
    """Parse URL into components."""
    result: dict[str, Any] = {"original": url_str}
    try:
        parsed = urlparse(url_str)
        if parsed.scheme:
            result["scheme"] = parsed.scheme
        if parsed.netloc:
            result["domain"] = parsed.hostname
            if parsed.port:
                result["port"] = parsed.port
        if parsed.path:
            result["path"] = parsed.path
        if parsed.query:
            result["query"] = parsed.query
        if parsed.fragment:
            result["fragment"] = parsed.fragment
    except Exception:
        result["path"] = url_str
    return result


@register_parser("nginx_apache", detector=_is_nginx_apache, priority=30)
def parse_nginx_apache(raw_data: Any) -> dict[str, Any]:
    """Parse Nginx/Apache combined access log to ECS format."""
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    match = COMBINED_RE.match(raw_str.strip())
    if not match:
        # Try simple pattern
        simple_match = SIMPLE_RE.match(raw_str.strip())
        if simple_match:
            client_ip = simple_match.group(1)
            ident = simple_match.group(2)
            auth_user = simple_match.group(3)
            timestamp_str = simple_match.group(4)
            request_line = simple_match.group(5)
            status = simple_match.group(6)
            size = simple_match.group(7)
            referrer = simple_match.group(8) if simple_match.lastindex and simple_match.lastindex >= 8 else None
            user_agent = simple_match.group(9) if simple_match.lastindex and simple_match.lastindex >= 9 else None
            xff = None

            # Split request line
            req_parts = request_line.split()
            method = req_parts[0] if len(req_parts) >= 1 else "-"
            url = req_parts[1] if len(req_parts) >= 2 else "-"
            protocol = req_parts[2] if len(req_parts) >= 3 else "-"
        else:
            raise ValueError(f"Not a valid Nginx/Apache combined log: {raw_str[:100]}")
    else:
        client_ip = match.group(1)
        ident = match.group(2)
        auth_user = match.group(3)
        timestamp_str = match.group(4)
        method = match.group(5)
        url = match.group(6)
        protocol = match.group(7)
        status = match.group(8)
        size = match.group(9)
        referrer = match.group(10) if match.lastindex and match.lastindex >= 10 else None
        user_agent = match.group(11) if match.lastindex and match.lastindex >= 11 else None
        xff = match.group(12) if match.lastindex and match.lastindex >= 12 else None

    ts_iso = _parse_clf_timestamp(timestamp_str)
    status_int = _safe_int(status) or 0
    size_int = _safe_int(size)
    url_fields = _parse_url(url)

    # Determine outcome from status code
    if status_int < 400:
        outcome = "success"
    elif status_int < 500:
        outcome = "failure"
    else:
        outcome = "failure"

    # Determine event type based on method
    event_type = ["access"]
    if method in ("POST", "PUT", "PATCH"):
        event_type.append("change")
    elif method == "DELETE":
        event_type.append("deletion")

    # Determine severity from status
    if status_int >= 500:
        severity = 70
    elif status_int >= 400:
        severity = 40
    elif status_int >= 300:
        severity = 20
    else:
        severity = 10

    # Extract HTTP version from protocol
    http_version = None
    if protocol and "/" in protocol:
        http_version = protocol.split("/", 1)[1]

    ecs: dict[str, Any] = {
        "@timestamp": ts_iso or datetime.utcnow().isoformat() + "Z",
        "message": f"{method} {url} {status}",
        "raw": raw_str,
        "event": {
            "kind": "event",
            "category": ["web"],
            "type": event_type,
            "action": "access",
            "outcome": outcome,
            "severity": severity,
            "module": "nginx",
            "dataset": "nginx.access",
        },
        "source": {
            "ip": client_ip,
        },
        "url": url_fields,
        "http": {
            "version": http_version,
            "request": {
                "method": method,
                "referrer": referrer if referrer and referrer != "-" else None,
            },
            "response": {
                "status_code": status_int,
                "bytes": size_int,
            },
        },
        "user_agent": {
            "original": user_agent if user_agent and user_agent != "-" else None,
        },
        "user": {
            "name": auth_user if auth_user and auth_user != "-" else None,
        },
        "related": {
            "ip": [client_ip],
        },
        "cybernest": {
            "parser_name": "nginx_apache",
            "parse_status": "success",
            "parser_version": "1.0.0",
        },
    }

    # Add X-Forwarded-For if present
    if xff and xff.strip() and xff != "-":
        xff_ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
        if xff_ips:
            ecs["source"]["ip"] = xff_ips[0]
            ecs["network"] = {"forwarded_ip": client_ip}
            ecs["related"]["ip"] = list(set([client_ip] + xff_ips))

    return ecs

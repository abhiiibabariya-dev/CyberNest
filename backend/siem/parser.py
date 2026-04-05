"""Log parser - normalizes raw logs into structured events."""

import re
from datetime import datetime, timezone
from typing import Optional


# Common log patterns
SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

CEF_PATTERN = re.compile(
    r"^CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extensions>.*)$"
)

JSON_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_syslog(raw: str) -> Optional[dict]:
    match = SYSLOG_PATTERN.match(raw)
    if not match:
        return None
    data = match.groupdict()
    return {
        "hostname": data.get("hostname"),
        "program": data.get("program"),
        "pid": data.get("pid"),
        "message": data.get("message"),
        "category": "syslog",
    }


def parse_cef(raw: str) -> Optional[dict]:
    match = CEF_PATTERN.match(raw)
    if not match:
        return None
    data = match.groupdict()
    extensions = {}
    for pair in re.findall(r"(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)", data.get("extensions", "")):
        extensions[pair[0]] = pair[1]
    return {
        "vendor": data.get("vendor"),
        "product": data.get("product"),
        "message": data.get("name"),
        "category": "cef",
        "src_ip": extensions.get("src"),
        "dst_ip": extensions.get("dst"),
        "severity_raw": data.get("severity"),
    }


def extract_ips(text: str) -> tuple[Optional[str], Optional[str]]:
    ips = JSON_IP_PATTERN.findall(text)
    src = ips[0] if len(ips) > 0 else None
    dst = ips[1] if len(ips) > 1 else None
    return src, dst


def parse_log(raw: str) -> dict:
    """Try all parsers and return normalized event data."""
    # Try syslog
    result = parse_syslog(raw)
    if result:
        src, dst = extract_ips(raw)
        result["src_ip"] = result.get("src_ip") or src
        result["dst_ip"] = result.get("dst_ip") or dst
        return result

    # Try CEF
    result = parse_cef(raw)
    if result:
        return result

    # Fallback: extract what we can
    src, dst = extract_ips(raw)
    return {
        "message": raw[:500],
        "category": "unknown",
        "src_ip": src,
        "dst_ip": dst,
        "hostname": None,
    }

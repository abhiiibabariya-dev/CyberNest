"""
CyberNest Linux auditd Parser.

Parses Linux auditd log entries in key=value format.
Handles record types: SYSCALL, EXECVE, PATH, PROCTITLE, USER_AUTH, USER_LOGIN.
Supports multi-record event reconstruction via audit_id (msg=audit(epoch:serial)).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.auditd")

# Main auditd line pattern: type=TYPE msg=audit(epoch:serial): key=value ...
AUDITD_RE = re.compile(
    r"^type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$"
)

# Alternate pattern with node= prefix
AUDITD_NODE_RE = re.compile(
    r"^node=(\S+)\s+type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)$"
)

# Key=value parser: handles both key=value and key="quoted value"
KV_RE = re.compile(r'''(\w+)=("(?:[^"\\]|\\.)*"|\S+)''')

# Hex-encoded string detection
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

# Syscall number to name (common x86_64 calls)
SYSCALL_NAMES: dict[str, str] = {
    "2": "open", "3": "close", "21": "access", "56": "clone",
    "57": "fork", "59": "execve", "62": "kill", "82": "rename",
    "83": "mkdir", "84": "rmdir", "85": "creat", "86": "link",
    "87": "unlink", "88": "symlink", "90": "chmod", "91": "fchmod",
    "92": "chown", "93": "fchown", "257": "openat", "258": "mkdirat",
    "259": "mknodat", "260": "fchownat", "263": "unlinkat",
    "264": "renameat", "265": "linkat", "268": "fchmodat",
    "288": "accept4", "298": "perf_event_open", "302": "prlimit64",
    "313": "finit_module", "314": "sched_setattr",
    "316": "renameat2", "319": "memfd_create",
    "322": "execveat", "323": "userfaultfd",
    "435": "clone3",
}


def _is_auditd(raw_data: Any) -> bool:
    """Detect auditd format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False
    return bool(AUDITD_RE.match(raw_str.strip()) or AUDITD_NODE_RE.match(raw_str.strip()))


def _decode_hex_string(hex_str: str) -> str:
    """Decode hex-encoded auditd string."""
    if not hex_str or not HEX_RE.match(hex_str):
        return hex_str
    try:
        return bytes.fromhex(hex_str).decode("utf-8", errors="replace").rstrip("\x00")
    except (ValueError, TypeError):
        return hex_str


def _parse_kv(kv_str: str) -> dict[str, str]:
    """Parse auditd key=value pairs."""
    result: dict[str, str] = {}
    for match in KV_RE.finditer(kv_str):
        key = match.group(1)
        value = match.group(2)
        # Strip quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        result[key] = value
    return result


def _safe_int(val: Optional[str]) -> Optional[int]:
    if val is None or val == "?" or val == "(null)":
        return None
    try:
        if val.startswith("0x") or val.startswith("0X"):
            return int(val, 16)
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_epoch(epoch_str: str) -> str:
    """Convert epoch string to ISO timestamp."""
    try:
        epoch = float(epoch_str)
        return datetime.utcfromtimestamp(epoch).isoformat() + "Z"
    except (ValueError, TypeError, OSError):
        return datetime.utcnow().isoformat() + "Z"


def _parse_syscall(kv: dict[str, str], base: dict[str, Any]) -> dict[str, Any]:
    """Parse SYSCALL record."""
    syscall_num = kv.get("syscall", "")
    syscall_name = SYSCALL_NAMES.get(syscall_num, f"unknown({syscall_num})")
    exe = kv.get("exe", "")
    comm = kv.get("comm", "")

    # Decode hex-encoded fields
    if exe and HEX_RE.match(exe.strip('"')):
        exe = _decode_hex_string(exe.strip('"'))
    if comm and HEX_RE.match(comm.strip('"')):
        comm = _decode_hex_string(comm.strip('"'))

    base["event"].update({
        "category": ["process"],
        "type": ["start"] if syscall_name == "execve" else ["info"],
        "action": f"syscall-{syscall_name}",
    })
    base["message"] = f"Syscall {syscall_name} by {comm} ({exe})"
    base["process"] = {
        "pid": _safe_int(kv.get("pid")),
        "name": _decode_hex_string(comm.strip('"')) if comm else None,
        "executable": _decode_hex_string(exe.strip('"')) if exe else None,
        "parent": {
            "pid": _safe_int(kv.get("ppid")),
        },
    }
    base["user"] = {
        "id": kv.get("uid"),
        "name": kv.get("auid") if kv.get("auid") != "4294967295" else None,
        "effective": {
            "id": kv.get("euid"),
        },
    }
    base["host"] = {
        "os": {"type": "linux"},
    }
    base["auditd"] = {
        "syscall": syscall_num,
        "syscall_name": syscall_name,
        "success": kv.get("success"),
        "exit": kv.get("exit"),
        "a0": kv.get("a0"),
        "a1": kv.get("a1"),
        "a2": kv.get("a2"),
        "a3": kv.get("a3"),
        "arch": kv.get("arch"),
        "tty": kv.get("tty"),
        "ses": kv.get("ses"),
        "key": kv.get("key"),
        "comm": comm,
        "exe": exe,
        "subj": kv.get("subj"),
    }
    return base


def _parse_execve(kv: dict[str, str], base: dict[str, Any]) -> dict[str, Any]:
    """Parse EXECVE record."""
    argc = _safe_int(kv.get("argc")) or 0
    args: list[str] = []
    for i in range(argc):
        arg = kv.get(f"a{i}", "")
        if arg and HEX_RE.match(arg.strip('"')):
            arg = _decode_hex_string(arg.strip('"'))
        else:
            arg = arg.strip('"')
        args.append(arg)

    command_line = " ".join(args)

    base["event"].update({
        "category": ["process"],
        "type": ["start"],
        "action": "process-execve",
    })
    base["message"] = f"EXECVE: {command_line[:300]}"
    base["process"] = {
        "args": args,
        "command_line": command_line,
        "name": args[0].rsplit("/", 1)[-1] if args else None,
        "executable": args[0] if args else None,
    }
    base["auditd"] = {
        "argc": argc,
        "args": args,
    }
    return base


def _parse_path(kv: dict[str, str], base: dict[str, Any]) -> dict[str, Any]:
    """Parse PATH record."""
    name = kv.get("name", "")
    if name and HEX_RE.match(name.strip('"')):
        name = _decode_hex_string(name.strip('"'))
    else:
        name = name.strip('"')

    base["event"].update({
        "category": ["file"],
        "type": ["access"],
        "action": "file-access",
    })
    base["message"] = f"PATH: {name} (mode={kv.get('mode', '')})"
    base["file"] = {
        "path": name,
        "name": name.rsplit("/", 1)[-1] if "/" in name else name,
        "inode": kv.get("inode"),
        "mode": kv.get("mode"),
        "uid": kv.get("ouid"),
        "gid": kv.get("ogid"),
        "type": kv.get("nametype"),
    }
    base["auditd"] = {
        "item": kv.get("item"),
        "nametype": kv.get("nametype"),
        "cap_fp": kv.get("cap_fp"),
        "cap_fi": kv.get("cap_fi"),
        "cap_fe": kv.get("cap_fe"),
        "cap_fver": kv.get("cap_fver"),
    }
    return base


def _parse_proctitle(kv: dict[str, str], base: dict[str, Any]) -> dict[str, Any]:
    """Parse PROCTITLE record."""
    proctitle = kv.get("proctitle", "")

    # Decode hex-encoded proctitle
    if proctitle and HEX_RE.match(proctitle):
        decoded = _decode_hex_string(proctitle)
        # Auditd encodes NUL as spaces in hex
        decoded = decoded.replace("\x00", " ").strip()
    else:
        decoded = proctitle.strip('"')

    base["event"].update({
        "category": ["process"],
        "type": ["info"],
        "action": "process-title",
    })
    base["message"] = f"PROCTITLE: {decoded[:300]}"
    base["process"] = {
        "title": decoded,
        "command_line": decoded,
    }
    base["auditd"] = {
        "proctitle_raw": proctitle,
        "proctitle": decoded,
    }
    return base


def _parse_user_auth(kv: dict[str, str], base: dict[str, Any]) -> dict[str, Any]:
    """Parse USER_AUTH record."""
    user = kv.get("acct", "") or kv.get("user", "")
    if user and HEX_RE.match(user.strip('"')):
        user = _decode_hex_string(user.strip('"'))
    else:
        user = user.strip('"')

    result = kv.get("res", "failed")
    outcome = "success" if result == "success" else "failure"
    op = kv.get("op", "")
    exe = kv.get("exe", "").strip('"')
    hostname = kv.get("hostname", "").strip('"')
    addr = kv.get("addr", "").strip('"')
    terminal = kv.get("terminal", "").strip('"')

    base["event"].update({
        "category": ["authentication"],
        "type": ["start"],
        "action": f"user-auth-{op}" if op else "user-auth",
        "outcome": outcome,
    })
    base["message"] = f"USER_AUTH: {user} op={op} res={result} from {addr}"
    base["user"] = {
        "name": user,
        "id": kv.get("uid"),
    }
    base["source"] = {
        "ip": addr if addr and addr != "?" else None,
        "domain": hostname if hostname and hostname != "?" else None,
    }
    base["process"] = {
        "executable": exe,
        "pid": _safe_int(kv.get("pid")),
    }
    base["auditd"] = {
        "op": op,
        "res": result,
        "terminal": terminal,
        "ses": kv.get("ses"),
        "subj": kv.get("subj"),
    }
    return base


def _parse_user_login(kv: dict[str, str], base: dict[str, Any]) -> dict[str, Any]:
    """Parse USER_LOGIN record."""
    user = kv.get("acct", "") or kv.get("user", "")
    if user and HEX_RE.match(user.strip('"')):
        user = _decode_hex_string(user.strip('"'))
    else:
        user = user.strip('"')

    result = kv.get("res", "failed")
    outcome = "success" if result == "success" else "failure"
    exe = kv.get("exe", "").strip('"')
    hostname = kv.get("hostname", "").strip('"')
    addr = kv.get("addr", "").strip('"')
    terminal = kv.get("terminal", "").strip('"')

    base["event"].update({
        "category": ["authentication"],
        "type": ["start"],
        "action": "user-login",
        "outcome": outcome,
    })
    base["message"] = f"USER_LOGIN: {user} res={result} from {addr} ({terminal})"
    base["user"] = {
        "name": user,
        "id": kv.get("uid"),
    }
    base["source"] = {
        "ip": addr if addr and addr != "?" else None,
        "domain": hostname if hostname and hostname != "?" else None,
    }
    base["process"] = {
        "executable": exe,
        "pid": _safe_int(kv.get("pid")),
    }
    base["auditd"] = {
        "op": kv.get("op"),
        "res": result,
        "terminal": terminal,
        "ses": kv.get("ses"),
        "subj": kv.get("subj"),
    }
    return base


_RECORD_PARSERS = {
    "SYSCALL": _parse_syscall,
    "EXECVE": _parse_execve,
    "PATH": _parse_path,
    "PROCTITLE": _parse_proctitle,
    "USER_AUTH": _parse_user_auth,
    "USER_LOGIN": _parse_user_login,
}


@register_parser("auditd", detector=_is_auditd, priority=20)
def parse_auditd(raw_data: Any) -> dict[str, Any]:
    """Parse a Linux auditd log entry to ECS format.

    Handles single records and multi-record events grouped by audit_id.
    """
    raw_str = raw_data if isinstance(raw_data, str) else (
        raw_data.get("raw", "") or raw_data.get("message", "")
    )

    stripped = raw_str.strip()

    # Parse header
    node = None
    match = AUDITD_NODE_RE.match(stripped)
    if match:
        node = match.group(1)
        record_type = match.group(2)
        epoch = match.group(3)
        serial = match.group(4)
        kv_str = match.group(5)
    else:
        match = AUDITD_RE.match(stripped)
        if not match:
            raise ValueError(f"Not a valid auditd log entry: {stripped[:100]}")
        record_type = match.group(1)
        epoch = match.group(2)
        serial = match.group(3)
        kv_str = match.group(4)

    kv = _parse_kv(kv_str)
    ts = _parse_epoch(epoch)
    audit_id = f"{epoch}:{serial}"

    # Build base ECS
    ecs: dict[str, Any] = {
        "@timestamp": ts,
        "raw": raw_str,
        "event": {
            "kind": "event",
            "module": "auditd",
            "dataset": f"auditd.{record_type.lower()}",
            "severity": 50,
            "id": audit_id,
        },
    }

    if node:
        ecs["host"] = {"name": node, "hostname": node}

    # Route to specific parser
    parser_func = _RECORD_PARSERS.get(record_type)
    if parser_func:
        ecs = parser_func(kv, ecs)
    else:
        # Generic fallback
        ecs["event"].update({
            "category": ["host"],
            "type": ["info"],
            "action": f"auditd-{record_type.lower()}",
        })
        ecs["message"] = f"auditd {record_type}: {kv_str[:200]}"
        ecs["auditd"] = {"record_type": record_type, **kv}

    # Set audit metadata
    ecs.setdefault("auditd", {}).update({
        "record_type": record_type,
        "audit_id": audit_id,
        "epoch": epoch,
        "serial": serial,
    })

    # Collect related
    related_ips: list[str] = []
    related_users: list[str] = []
    src_ip = (ecs.get("source") or {}).get("ip")
    if src_ip:
        related_ips.append(src_ip)
    user_name = (ecs.get("user") or {}).get("name")
    if user_name:
        related_users.append(user_name)

    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related:
        ecs.setdefault("related", {}).update(related)

    ecs["cybernest"] = {
        "parser_name": "auditd",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs


def reconstruct_auditd_event(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct a multi-record auditd event from individual parsed records.

    Merges SYSCALL + EXECVE + PATH + PROCTITLE records sharing the same audit_id
    into a single enriched ECS event.

    Args:
        records: List of parsed auditd ECS dicts sharing the same audit_id.

    Returns:
        Merged ECS event dictionary.
    """
    if not records:
        raise ValueError("No records to reconstruct")

    if len(records) == 1:
        return records[0]

    # Use SYSCALL as the base if present, otherwise first record
    base = None
    for r in records:
        if (r.get("auditd") or {}).get("record_type") == "SYSCALL":
            base = r.copy()
            break
    if base is None:
        base = records[0].copy()

    # Merge fields from other records
    for r in records:
        record_type = (r.get("auditd") or {}).get("record_type", "")
        if record_type == "SYSCALL" and r is not base:
            continue

        if record_type == "EXECVE" and r.get("process"):
            proc = base.setdefault("process", {})
            proc["command_line"] = r["process"].get("command_line") or proc.get("command_line")
            proc["args"] = r["process"].get("args") or proc.get("args")
            if r["process"].get("executable"):
                proc["executable"] = r["process"]["executable"]

        elif record_type == "PATH" and r.get("file"):
            base["file"] = r["file"]
            base["event"]["category"] = list(set(
                base.get("event", {}).get("category", []) + ["file"]
            ))

        elif record_type == "PROCTITLE" and r.get("process"):
            proc = base.setdefault("process", {})
            if not proc.get("command_line"):
                proc["command_line"] = r["process"].get("command_line")
            proc["title"] = r["process"].get("title")

    # Merge audit metadata
    all_types = [
        (r.get("auditd") or {}).get("record_type", "")
        for r in records
    ]
    base.setdefault("auditd", {})["record_types"] = all_types

    # Merge raw
    all_raw = [r.get("raw", "") for r in records if r.get("raw")]
    base["raw"] = "\n".join(all_raw)

    return base

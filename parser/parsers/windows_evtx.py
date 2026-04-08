"""
CyberNest Windows Event Log (EVTX XML) Parser.

Parses Windows XML Event Log entries and maps them to ECS fields.
Covers all major security-relevant EventIDs with full field extraction.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from lxml import etree

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.windows_evtx")

# Windows Event Log XML namespace
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Logon type descriptions
LOGON_TYPES: dict[str, str] = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
    "12": "CachedRemoteInteractive",
    "13": "CachedUnlock",
}

# Kerberos result codes
KERBEROS_RESULT_CODES: dict[str, str] = {
    "0x0": "KDC_ERR_NONE (Success)",
    "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "0x7": "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    "0xc": "KDC_ERR_POLICY",
    "0x12": "KDC_ERR_CLIENT_REVOKED",
    "0x17": "KDC_ERR_KEY_EXPIRED",
    "0x18": "KDC_ERR_PREAUTH_FAILED",
    "0x25": "KDC_ERR_PREAUTH_REQUIRED",
}

# Sub-status codes for failed logon
LOGON_FAILURE_SUBSTATUS: dict[str, str] = {
    "0xc0000064": "User name does not exist",
    "0xc000006a": "Incorrect password",
    "0xc0000234": "Account locked out",
    "0xc0000072": "Account disabled",
    "0xc000006f": "Logon outside authorized hours",
    "0xc0000070": "Unauthorized workstation",
    "0xc0000071": "Password expired",
    "0xc0000193": "Account expired",
    "0xc0000224": "Password must change at next logon",
    "0xc0000413": "Authentication firewall",
}


def _is_windows_evtx(raw_data: Any) -> bool:
    """Detect Windows Event XML format."""
    if isinstance(raw_data, dict):
        raw_str = raw_data.get("raw", "") or raw_data.get("message", "")
    elif isinstance(raw_data, str):
        raw_str = raw_data
    else:
        return False
    return "<Event xmlns" in raw_str or ("<Event>" in raw_str and "<System>" in raw_str)


def _get_xml(raw_data: Any) -> str:
    """Extract XML string from raw data."""
    if isinstance(raw_data, dict):
        return raw_data.get("raw", "") or raw_data.get("message", "")
    return str(raw_data)


def _xpath_text(root: etree._Element, xpath: str) -> Optional[str]:
    """Extract text from xpath, returning None if not found."""
    result = root.xpath(xpath, namespaces=NS)
    if result:
        el = result[0]
        if isinstance(el, etree._Element):
            return el.text
        return str(el)
    return None


def _get_event_data(root: etree._Element) -> dict[str, str]:
    """Extract all EventData Name=Value pairs into a dict."""
    data: dict[str, str] = {}
    # Try namespaced first
    for el in root.xpath("//e:EventData/e:Data[@Name]", namespaces=NS):
        name = el.get("Name", "")
        data[name] = (el.text or "").strip()
    # Try non-namespaced
    if not data:
        for el in root.xpath("//EventData/Data[@Name]"):
            name = el.get("Name", "")
            data[name] = (el.text or "").strip()
    return data


def _get_system_fields(root: etree._Element) -> dict[str, Any]:
    """Extract System element fields."""
    fields: dict[str, Any] = {}

    # Try namespaced
    event_id = _xpath_text(root, "//e:System/e:EventID")
    if event_id is None:
        event_id = _xpath_text(root, "//System/EventID")
    fields["event_id"] = event_id

    provider = root.xpath("//e:System/e:Provider/@Name", namespaces=NS)
    if not provider:
        provider = root.xpath("//System/Provider/@Name")
    fields["provider"] = provider[0] if provider else None

    fields["channel"] = (
        _xpath_text(root, "//e:System/e:Channel")
        or _xpath_text(root, "//System/Channel")
    )
    fields["computer"] = (
        _xpath_text(root, "//e:System/e:Computer")
        or _xpath_text(root, "//System/Computer")
    )
    fields["time_created"] = None
    tc = root.xpath("//e:System/e:TimeCreated/@SystemTime", namespaces=NS)
    if not tc:
        tc = root.xpath("//System/TimeCreated/@SystemTime")
    if tc:
        fields["time_created"] = tc[0]

    fields["level"] = (
        _xpath_text(root, "//e:System/e:Level")
        or _xpath_text(root, "//System/Level")
    )
    fields["task"] = (
        _xpath_text(root, "//e:System/e:Task")
        or _xpath_text(root, "//System/Task")
    )
    fields["keywords"] = (
        _xpath_text(root, "//e:System/e:Keywords")
        or _xpath_text(root, "//System/Keywords")
    )

    return fields


def _safe_int(val: Optional[str]) -> Optional[int]:
    """Convert string to int, returning None on failure."""
    if val is None:
        return None
    try:
        if val.startswith("0x") or val.startswith("0X"):
            return int(val, 16)
        return int(val)
    except (ValueError, TypeError):
        return None


def _collect_related(ecs: dict[str, Any]) -> None:
    """Populate related.ip, related.user, related.hosts from known fields."""
    ips: list[str] = []
    users: list[str] = []
    hosts: list[str] = []

    src_ip = (ecs.get("source") or {}).get("ip")
    if src_ip and src_ip != "-":
        ips.append(src_ip)
    dst_ip = (ecs.get("destination") or {}).get("ip")
    if dst_ip and dst_ip != "-":
        ips.append(dst_ip)

    user_name = (ecs.get("user") or {}).get("name")
    if user_name and user_name != "-":
        users.append(user_name)
    target_user = ((ecs.get("user") or {}).get("target") or {}).get("name")
    if target_user and target_user != "-":
        users.append(target_user)

    host_name = (ecs.get("host") or {}).get("name")
    if host_name:
        hosts.append(host_name)

    if ips or users or hosts:
        ecs["related"] = {}
        if ips:
            ecs["related"]["ip"] = list(set(ips))
        if users:
            ecs["related"]["user"] = list(set(users))
        if hosts:
            ecs["related"]["hosts"] = list(set(hosts))


def _parse_timestamp(ts_str: Optional[str]) -> Optional[str]:
    """Parse Windows timestamp to ISO format."""
    if not ts_str:
        return None
    try:
        # Handle various Windows timestamp formats
        ts_str = ts_str.rstrip("Z")
        if "." in ts_str:
            # Truncate to 6 decimal places for microseconds
            parts = ts_str.split(".")
            frac = parts[1][:6]
            ts_str = f"{parts[0]}.{frac}"
        dt = datetime.fromisoformat(ts_str)
        return dt.isoformat() + "Z"
    except (ValueError, TypeError):
        return ts_str


# ---------------------------------------------------------------------------
# Per-EventID parsers
# ---------------------------------------------------------------------------

def _parse_4624(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Logon success."""
    logon_type = event_data.get("LogonType", "")
    logon_type_desc = LOGON_TYPES.get(logon_type, f"Unknown({logon_type})")
    target_user = event_data.get("TargetUserName", "")
    target_domain = event_data.get("TargetDomainName", "")
    src_ip = event_data.get("IpAddress", "-")
    src_port = event_data.get("IpPort", "0")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
            "action": "logon-success",
            "outcome": "success",
            "code": "4624",
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Successful logon: {target_domain}\\{target_user} (Type {logon_type}: {logon_type_desc})",
        "user": {
            "name": target_user,
            "domain": target_domain,
            "id": event_data.get("TargetUserSid", ""),
            "target": {
                "name": target_user,
                "domain": target_domain,
            },
        },
        "source": {
            "ip": src_ip if src_ip != "-" else None,
            "port": _safe_int(src_port),
        },
        "host": {
            "name": sys_fields.get("computer"),
        },
        "winlog": {
            "logon_type": logon_type,
            "logon_type_description": logon_type_desc,
            "logon_id": event_data.get("TargetLogonId", ""),
            "subject_user_name": event_data.get("SubjectUserName", ""),
            "subject_domain_name": event_data.get("SubjectDomainName", ""),
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
            "authentication_package": event_data.get("AuthenticationPackageName", ""),
            "logon_process": event_data.get("LogonProcessName", ""),
            "workstation_name": event_data.get("WorkstationName", ""),
            "elevated_token": event_data.get("ElevatedToken", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_4625(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Failed logon."""
    logon_type = event_data.get("LogonType", "")
    logon_type_desc = LOGON_TYPES.get(logon_type, f"Unknown({logon_type})")
    target_user = event_data.get("TargetUserName", "")
    target_domain = event_data.get("TargetDomainName", "")
    src_ip = event_data.get("IpAddress", "-")
    status = event_data.get("Status", "").lower()
    sub_status = event_data.get("SubStatus", "").lower()
    failure_reason = LOGON_FAILURE_SUBSTATUS.get(
        sub_status, LOGON_FAILURE_SUBSTATUS.get(status, "Unknown")
    )

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
            "action": "logon-failed",
            "outcome": "failure",
            "code": "4625",
            "reason": failure_reason,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Failed logon: {target_domain}\\{target_user} (Type {logon_type}: {logon_type_desc}) - {failure_reason}",
        "user": {
            "name": target_user,
            "domain": target_domain,
            "id": event_data.get("TargetUserSid", ""),
        },
        "source": {
            "ip": src_ip if src_ip != "-" else None,
            "port": _safe_int(event_data.get("IpPort", "0")),
        },
        "host": {
            "name": sys_fields.get("computer"),
        },
        "winlog": {
            "logon_type": logon_type,
            "logon_type_description": logon_type_desc,
            "status": status,
            "sub_status": sub_status,
            "failure_reason": failure_reason,
            "subject_user_name": event_data.get("SubjectUserName", ""),
            "subject_domain_name": event_data.get("SubjectDomainName", ""),
            "authentication_package": event_data.get("AuthenticationPackageName", ""),
            "logon_process": event_data.get("LogonProcessName", ""),
            "workstation_name": event_data.get("WorkstationName", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_logoff(sys_fields: dict, event_data: dict, event_id: str) -> dict[str, Any]:
    """4634 / 4647 Logoff."""
    target_user = event_data.get("TargetUserName", "")
    target_domain = event_data.get("TargetDomainName", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["authentication"],
            "type": ["end"],
            "action": "logoff",
            "outcome": "success",
            "code": event_id,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Logoff: {target_domain}\\{target_user}",
        "user": {
            "name": target_user,
            "domain": target_domain,
            "id": event_data.get("TargetUserSid", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "logon_id": event_data.get("TargetLogonId", ""),
            "logon_type": event_data.get("LogonType", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_4648(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Explicit credentials logon."""
    subject_user = event_data.get("SubjectUserName", "")
    target_user = event_data.get("TargetUserName", "")
    target_server = event_data.get("TargetServerName", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
            "action": "explicit-credentials-logon",
            "outcome": "success",
            "code": "4648",
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Explicit credentials used by {subject_user} to logon to {target_server} as {target_user}",
        "user": {
            "name": subject_user,
            "domain": event_data.get("SubjectDomainName", ""),
            "target": {
                "name": target_user,
                "domain": event_data.get("TargetDomainName", ""),
            },
        },
        "source": {
            "ip": event_data.get("IpAddress", None),
            "port": _safe_int(event_data.get("IpPort")),
        },
        "host": {"name": sys_fields.get("computer")},
        "destination": {"domain": target_server},
        "winlog": {
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
            "target_server_name": target_server,
            "process_name": event_data.get("ProcessName", ""),
            "process_id": event_data.get("ProcessId", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_4657(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Registry value modified."""
    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["registry"],
            "type": ["change"],
            "action": "registry-value-modified",
            "outcome": "success",
            "code": "4657",
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Registry value modified: {event_data.get('ObjectName', '')}\\{event_data.get('ObjectValueName', '')}",
        "user": {
            "name": event_data.get("SubjectUserName", ""),
            "domain": event_data.get("SubjectDomainName", ""),
            "id": event_data.get("SubjectUserSid", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "object_name": event_data.get("ObjectName", ""),
            "object_value_name": event_data.get("ObjectValueName", ""),
            "old_value": event_data.get("OldValue", ""),
            "new_value": event_data.get("NewValue", ""),
            "old_value_type": event_data.get("OldValueType", ""),
            "new_value_type": event_data.get("NewValueType", ""),
            "operation_type": event_data.get("OperationType", ""),
            "process_name": event_data.get("ProcessName", ""),
            "process_id": event_data.get("ProcessId", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_4663(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Object access attempt."""
    object_name = event_data.get("ObjectName", "")
    object_type = event_data.get("ObjectType", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["file"],
            "type": ["access"],
            "action": "object-access",
            "outcome": "success",
            "code": "4663",
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Object access: {object_type} '{object_name}' by {event_data.get('SubjectUserName', '')}",
        "file": {
            "path": object_name if object_type == "File" else None,
            "name": object_name.rsplit("\\", 1)[-1] if "\\" in object_name and object_type == "File" else None,
        },
        "user": {
            "name": event_data.get("SubjectUserName", ""),
            "domain": event_data.get("SubjectDomainName", ""),
            "id": event_data.get("SubjectUserSid", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "process": {
            "pid": _safe_int(event_data.get("ProcessId")),
            "name": event_data.get("ProcessName", "").rsplit("\\", 1)[-1] if event_data.get("ProcessName") else None,
            "executable": event_data.get("ProcessName"),
        },
        "winlog": {
            "object_type": object_type,
            "object_name": object_name,
            "handle_id": event_data.get("HandleId", ""),
            "access_list": event_data.get("AccessList", ""),
            "access_mask": event_data.get("AccessMask", ""),
            "resource_attributes": event_data.get("ResourceAttributes", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_4672(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Special privileges assigned to new logon."""
    user_name = event_data.get("SubjectUserName", "")
    privileges = event_data.get("PrivilegeList", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["iam"],
            "type": ["admin"],
            "action": "special-privileges-logon",
            "outcome": "success",
            "code": "4672",
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Special privileges assigned to {event_data.get('SubjectDomainName', '')}\\{user_name}",
        "user": {
            "name": user_name,
            "domain": event_data.get("SubjectDomainName", ""),
            "id": event_data.get("SubjectUserSid", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "logon_id": event_data.get("SubjectLogonId", ""),
            "privileges": [p.strip() for p in privileges.split("\n") if p.strip()],
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_4688(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Process creation."""
    new_process = event_data.get("NewProcessName", "")
    parent_process = event_data.get("ParentProcessName", "")
    command_line = event_data.get("CommandLine", "")
    process_name = new_process.rsplit("\\", 1)[-1] if new_process else ""
    parent_name = parent_process.rsplit("\\", 1)[-1] if parent_process else ""

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process-created",
            "outcome": "success",
            "code": "4688",
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Process created: {process_name} (CommandLine: {command_line[:200]})",
        "process": {
            "pid": _safe_int(event_data.get("NewProcessId")),
            "name": process_name,
            "executable": new_process,
            "command_line": command_line,
            "args": command_line.split() if command_line else [],
            "parent": {
                "pid": _safe_int(event_data.get("ProcessId")),
                "name": parent_name,
                "executable": parent_process,
            },
        },
        "user": {
            "name": event_data.get("SubjectUserName", ""),
            "domain": event_data.get("SubjectDomainName", ""),
            "id": event_data.get("SubjectUserSid", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "token_elevation_type": event_data.get("TokenElevationType", ""),
            "mandatory_label": event_data.get("MandatoryLabel", ""),
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
            "target_logon_id": event_data.get("TargetLogonId", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_service_install(sys_fields: dict, event_data: dict, event_id: str) -> dict[str, Any]:
    """4697 / 7045 Service installed."""
    service_name = event_data.get("ServiceName", "")
    service_file = event_data.get("ServiceFileName", "") or event_data.get("ImagePath", "")
    service_type = event_data.get("ServiceType", "")
    service_start = event_data.get("ServiceStartType", "") or event_data.get("StartType", "")
    account = event_data.get("ServiceAccount", "") or event_data.get("AccountName", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["configuration"],
            "type": ["installation"],
            "action": "service-installed",
            "outcome": "success",
            "code": event_id,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security" if event_id == "4697" else "windows.system",
        },
        "message": f"Service installed: {service_name} ({service_file})",
        "service": {
            "name": service_name,
            "type": service_type,
        },
        "user": {
            "name": event_data.get("SubjectUserName", account),
            "domain": event_data.get("SubjectDomainName", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "service_file_name": service_file,
            "service_type": service_type,
            "service_start_type": service_start,
            "service_account": account,
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_scheduled_task(sys_fields: dict, event_data: dict, event_id: str) -> dict[str, Any]:
    """4698 / 4702 Scheduled task created/updated."""
    task_name = event_data.get("TaskName", "")
    action = "scheduled-task-created" if event_id == "4698" else "scheduled-task-updated"

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["configuration"],
            "type": ["creation"] if event_id == "4698" else ["change"],
            "action": action,
            "outcome": "success",
            "code": event_id,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Scheduled task {'created' if event_id == '4698' else 'updated'}: {task_name}",
        "user": {
            "name": event_data.get("SubjectUserName", ""),
            "domain": event_data.get("SubjectDomainName", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "task_name": task_name,
            "task_content": event_data.get("TaskContent", ""),
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_account_mgmt(sys_fields: dict, event_data: dict, event_id: str) -> dict[str, Any]:
    """4720-4726 Account management events."""
    actions_map = {
        "4720": ("user-account-created", ["creation"]),
        "4721": ("user-account-deleted", ["deletion"]),  # Actual: password set
        "4722": ("user-account-enabled", ["change"]),
        "4723": ("password-change-attempt", ["change"]),
        "4724": ("password-reset-attempt", ["change"]),
        "4725": ("user-account-disabled", ["change"]),
        "4726": ("user-account-deleted", ["deletion"]),
    }
    action_name, event_types = actions_map.get(event_id, ("account-management", ["change"]))
    target_user = event_data.get("TargetUserName", "")
    target_domain = event_data.get("TargetDomainName", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["iam"],
            "type": event_types,
            "action": action_name,
            "outcome": "success",
            "code": event_id,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Account {action_name}: {target_domain}\\{target_user}",
        "user": {
            "name": event_data.get("SubjectUserName", ""),
            "domain": event_data.get("SubjectDomainName", ""),
            "target": {
                "name": target_user,
                "domain": target_domain,
                "id": event_data.get("TargetSid", ""),
            },
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
            "privilege_list": event_data.get("PrivilegeList", ""),
            "sam_account_name": event_data.get("SamAccountName", ""),
            "display_name": event_data.get("DisplayName", ""),
            "user_principal_name": event_data.get("UserPrincipalName", ""),
            "home_directory": event_data.get("HomeDirectory", ""),
            "home_path": event_data.get("HomePath", ""),
            "script_path": event_data.get("ScriptPath", ""),
            "profile_path": event_data.get("ProfilePath", ""),
            "user_workstations": event_data.get("UserWorkstations", ""),
            "password_last_set": event_data.get("PasswordLastSet", ""),
            "account_expires": event_data.get("AccountExpires", ""),
            "primary_group_id": event_data.get("PrimaryGroupId", ""),
            "user_account_control": event_data.get("UserAccountControl", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_group_membership(sys_fields: dict, event_data: dict, event_id: str) -> dict[str, Any]:
    """4728/4732/4756 Group membership change."""
    groups_map = {
        "4728": "global-group",
        "4732": "local-group",
        "4756": "universal-group",
    }
    group_type = groups_map.get(event_id, "group")
    member = event_data.get("MemberName", "") or event_data.get("MemberSid", "")
    group_name = event_data.get("TargetUserName", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["iam"],
            "type": ["group", "change"],
            "action": f"member-added-{group_type}",
            "outcome": "success",
            "code": event_id,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Member added to {group_type}: {member} -> {event_data.get('TargetDomainName', '')}\\{group_name}",
        "user": {
            "name": event_data.get("SubjectUserName", ""),
            "domain": event_data.get("SubjectDomainName", ""),
            "target": {
                "name": member,
                "group": {
                    "name": group_name,
                    "domain": event_data.get("TargetDomainName", ""),
                    "id": event_data.get("TargetSid", ""),
                },
            },
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "member_name": member,
            "member_sid": event_data.get("MemberSid", ""),
            "group_name": group_name,
            "group_domain": event_data.get("TargetDomainName", ""),
            "group_sid": event_data.get("TargetSid", ""),
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_4740(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Account lockout."""
    target_user = event_data.get("TargetUserName", "")
    target_domain = event_data.get("TargetDomainName", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["iam", "authentication"],
            "type": ["change"],
            "action": "account-locked-out",
            "outcome": "success",
            "code": "4740",
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Account locked out: {target_domain}\\{target_user}",
        "user": {
            "name": target_user,
            "domain": target_domain,
            "id": event_data.get("TargetSid", ""),
        },
        "source": {
            "domain": event_data.get("TargetDomainName", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "subject_user_name": event_data.get("SubjectUserName", ""),
            "subject_domain_name": event_data.get("SubjectDomainName", ""),
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_kerberos(sys_fields: dict, event_data: dict, event_id: str) -> dict[str, Any]:
    """4768/4769/4771/4776 Kerberos and NTLM authentication."""
    actions_map = {
        "4768": "kerberos-tgs-requested",
        "4769": "kerberos-service-ticket-requested",
        "4771": "kerberos-preauth-failed",
        "4776": "ntlm-credential-validation",
    }
    action = actions_map.get(event_id, "kerberos-auth")

    target_user = event_data.get("TargetUserName", "")
    target_domain = event_data.get("TargetDomainName", "") or event_data.get("Workstation", "")
    client_addr = event_data.get("IpAddress", "") or event_data.get("ClientAddress", "")
    if client_addr and client_addr.startswith("::ffff:"):
        client_addr = client_addr[7:]

    result_code = event_data.get("Status", "") or event_data.get("ResultCode", "")
    is_failure = event_id in ("4771",) or (result_code and result_code != "0x0")
    outcome = "failure" if is_failure else "success"
    failure_desc = KERBEROS_RESULT_CODES.get(result_code, "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["authentication"],
            "type": ["start"],
            "action": action,
            "outcome": outcome,
            "code": event_id,
            "reason": failure_desc if is_failure else None,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"{action}: {target_user}@{target_domain} result={result_code} {failure_desc}",
        "user": {
            "name": target_user,
            "domain": target_domain,
        },
        "source": {
            "ip": client_addr if client_addr and client_addr != "-" else None,
            "port": _safe_int(event_data.get("IpPort") or event_data.get("ClientPort")),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "result_code": result_code,
            "failure_code": failure_desc,
            "ticket_encryption_type": event_data.get("TicketEncryptionType", ""),
            "service_name": event_data.get("ServiceName", ""),
            "service_sid": event_data.get("ServiceSid", ""),
            "pre_auth_type": event_data.get("PreAuthType", ""),
            "certificate_issuer_name": event_data.get("CertIssuerName", ""),
            "certificate_serial_number": event_data.get("CertSerialNumber", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_1102(sys_fields: dict, event_data: dict) -> dict[str, Any]:
    """Audit log cleared."""
    ecs: dict[str, Any] = {
        "event": {
            "kind": "alert",
            "category": ["configuration"],
            "type": ["deletion"],
            "action": "audit-log-cleared",
            "outcome": "success",
            "code": "1102",
            "severity": 80,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.security",
        },
        "message": f"Security audit log cleared by {event_data.get('SubjectUserName', 'UNKNOWN')}",
        "user": {
            "name": event_data.get("SubjectUserName", ""),
            "domain": event_data.get("SubjectDomainName", ""),
            "id": event_data.get("SubjectUserSid", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "subject_logon_id": event_data.get("SubjectLogonId", ""),
        },
    }
    _collect_related(ecs)
    return ecs


def _parse_powershell(sys_fields: dict, event_data: dict, event_id: str) -> dict[str, Any]:
    """4104/4103 PowerShell script block / module logging."""
    script_block = event_data.get("ScriptBlockText", "") or event_data.get("Payload", "")
    action = "powershell-scriptblock" if event_id == "4104" else "powershell-module-logging"
    path = event_data.get("ScriptBlockId", "") or event_data.get("Path", "")

    ecs: dict[str, Any] = {
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["info"],
            "action": action,
            "outcome": "success",
            "code": event_id,
            "provider": sys_fields.get("provider"),
            "module": "windows",
            "dataset": "windows.powershell",
        },
        "message": f"PowerShell: {script_block[:300]}",
        "process": {
            "name": "powershell.exe",
            "command_line": script_block[:4096],
            "title": path,
        },
        "user": {
            "name": event_data.get("SubjectUserName", "") or event_data.get("UserId", ""),
        },
        "host": {"name": sys_fields.get("computer")},
        "winlog": {
            "script_block_id": event_data.get("ScriptBlockId", ""),
            "script_block_text": script_block,
            "message_number": event_data.get("MessageNumber", ""),
            "message_total": event_data.get("MessageTotal", ""),
            "path": event_data.get("Path", ""),
        },
    }
    _collect_related(ecs)
    return ecs


# ---------------------------------------------------------------------------
# Event ID dispatcher
# ---------------------------------------------------------------------------

_EVENT_PARSERS: dict[str, Any] = {
    "4624": lambda s, d: _parse_4624(s, d),
    "4625": lambda s, d: _parse_4625(s, d),
    "4634": lambda s, d: _parse_logoff(s, d, "4634"),
    "4647": lambda s, d: _parse_logoff(s, d, "4647"),
    "4648": lambda s, d: _parse_4648(s, d),
    "4657": lambda s, d: _parse_4657(s, d),
    "4663": lambda s, d: _parse_4663(s, d),
    "4672": lambda s, d: _parse_4672(s, d),
    "4688": lambda s, d: _parse_4688(s, d),
    "4697": lambda s, d: _parse_service_install(s, d, "4697"),
    "7045": lambda s, d: _parse_service_install(s, d, "7045"),
    "4698": lambda s, d: _parse_scheduled_task(s, d, "4698"),
    "4702": lambda s, d: _parse_scheduled_task(s, d, "4702"),
    "4720": lambda s, d: _parse_account_mgmt(s, d, "4720"),
    "4721": lambda s, d: _parse_account_mgmt(s, d, "4721"),
    "4722": lambda s, d: _parse_account_mgmt(s, d, "4722"),
    "4723": lambda s, d: _parse_account_mgmt(s, d, "4723"),
    "4724": lambda s, d: _parse_account_mgmt(s, d, "4724"),
    "4725": lambda s, d: _parse_account_mgmt(s, d, "4725"),
    "4726": lambda s, d: _parse_account_mgmt(s, d, "4726"),
    "4728": lambda s, d: _parse_group_membership(s, d, "4728"),
    "4732": lambda s, d: _parse_group_membership(s, d, "4732"),
    "4756": lambda s, d: _parse_group_membership(s, d, "4756"),
    "4740": lambda s, d: _parse_4740(s, d),
    "4768": lambda s, d: _parse_kerberos(s, d, "4768"),
    "4769": lambda s, d: _parse_kerberos(s, d, "4769"),
    "4771": lambda s, d: _parse_kerberos(s, d, "4771"),
    "4776": lambda s, d: _parse_kerberos(s, d, "4776"),
    "1102": lambda s, d: _parse_1102(s, d),
    "4104": lambda s, d: _parse_powershell(s, d, "4104"),
    "4103": lambda s, d: _parse_powershell(s, d, "4103"),
}


@register_parser("windows_evtx", detector=_is_windows_evtx, priority=10)
def parse_windows_evtx(raw_data: Any) -> dict[str, Any]:
    """Parse a Windows Event Log XML entry to ECS format.

    Args:
        raw_data: Raw XML string or dict with 'raw'/'message' key containing XML.

    Returns:
        ECS-normalized event dictionary.
    """
    xml_str = _get_xml(raw_data)
    if not xml_str:
        raise ValueError("Empty Windows Event XML")

    try:
        root = etree.fromstring(xml_str.encode("utf-8") if isinstance(xml_str, str) else xml_str)
    except etree.XMLSyntaxError as exc:
        raise ValueError(f"Invalid Windows Event XML: {exc}") from exc

    sys_fields = _get_system_fields(root)
    event_data = _get_event_data(root)
    event_id = sys_fields.get("event_id", "")

    # Route to specific parser
    parser_func = _EVENT_PARSERS.get(event_id)
    if parser_func:
        ecs = parser_func(sys_fields, event_data)
    else:
        # Generic fallback for unknown event IDs
        ecs = {
            "event": {
                "kind": "event",
                "category": ["host"],
                "type": ["info"],
                "action": f"windows-event-{event_id}",
                "outcome": "success",
                "code": event_id,
                "provider": sys_fields.get("provider"),
                "module": "windows",
                "dataset": f"windows.{sys_fields.get('channel', 'unknown').lower().replace(' ', '_')}",
            },
            "message": f"Windows Event {event_id}",
            "host": {"name": sys_fields.get("computer")},
        }
        # Add all event data as winlog fields
        ecs["winlog"] = event_data
        _collect_related(ecs)

    # Add timestamp
    ts = _parse_timestamp(sys_fields.get("time_created"))
    if ts:
        ecs["@timestamp"] = ts

    # Store original XML
    ecs["raw"] = xml_str

    # Add Windows-specific metadata
    if "winlog" not in ecs:
        ecs["winlog"] = {}
    ecs["winlog"]["channel"] = sys_fields.get("channel")
    ecs["winlog"]["provider_name"] = sys_fields.get("provider")
    ecs["winlog"]["event_id"] = event_id

    # Set cybernest metadata
    ecs["cybernest"] = {
        "parser_name": "windows_evtx",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs

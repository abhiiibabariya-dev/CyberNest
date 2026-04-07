"""CyberNest Parser — Windows Event Log (XML) parser."""

import re
import xml.etree.ElementTree as ET
from app.parsers.base import BaseParser, ECSEvent

# Common Windows Event IDs and their meaning
WINDOWS_EVENT_MAP = {
    # Authentication
    4624: ("authentication", "logon_success", "Successful logon"),
    4625: ("authentication", "logon_failure", "Failed logon"),
    4634: ("authentication", "logoff", "Logoff"),
    4648: ("authentication", "explicit_logon", "Logon with explicit credentials"),
    4768: ("authentication", "kerberos_tgt_request", "Kerberos TGT requested"),
    4769: ("authentication", "kerberos_service_ticket", "Kerberos service ticket requested"),
    4771: ("authentication", "kerberos_preauth_failed", "Kerberos pre-authentication failed"),
    # Account management
    4720: ("iam", "user_created", "User account created"),
    4722: ("iam", "user_enabled", "User account enabled"),
    4724: ("iam", "password_reset", "Password reset attempted"),
    4725: ("iam", "user_disabled", "User account disabled"),
    4726: ("iam", "user_deleted", "User account deleted"),
    4728: ("iam", "group_member_added", "Member added to security group"),
    4732: ("iam", "group_member_added", "Member added to local group"),
    4756: ("iam", "group_member_added", "Member added to universal group"),
    # Privilege use
    4672: ("iam", "special_privileges", "Special privileges assigned"),
    4673: ("iam", "privileged_service", "Privileged service called"),
    # Process
    4688: ("process", "process_created", "New process created"),
    4689: ("process", "process_terminated", "Process terminated"),
    # Object access
    4663: ("file", "file_access", "Object access attempted"),
    4656: ("file", "handle_request", "Handle to object requested"),
    # Policy changes
    4719: ("configuration", "audit_policy_changed", "System audit policy changed"),
    4739: ("configuration", "domain_policy_changed", "Domain policy changed"),
    # System
    7045: ("package", "service_installed", "New service installed"),
    1102: ("configuration", "audit_log_cleared", "Audit log cleared"),
    # PowerShell
    4103: ("process", "powershell_pipeline", "PowerShell pipeline execution"),
    4104: ("process", "powershell_scriptblock", "PowerShell ScriptBlock logging"),
    # Sysmon
    1: ("process", "process_created", "Sysmon: Process created"),
    3: ("network", "connection_detected", "Sysmon: Network connection"),
    7: ("library", "image_loaded", "Sysmon: Image loaded"),
    8: ("process", "createremotethread", "Sysmon: CreateRemoteThread"),
    10: ("process", "process_access", "Sysmon: Process accessed"),
    11: ("file", "file_created", "Sysmon: File created"),
    13: ("registry", "registry_value_set", "Sysmon: Registry value set"),
    22: ("network", "dns_query", "Sysmon: DNS query"),
}

# Logon type mapping
LOGON_TYPES = {
    "2": "interactive", "3": "network", "4": "batch", "5": "service",
    "7": "unlock", "8": "network_cleartext", "9": "new_credentials",
    "10": "remote_interactive", "11": "cached_interactive",
}


class WindowsEventParser(BaseParser):
    name = "windows_event"
    supported_formats = ["windows_xml", "evtx"]

    def can_parse(self, raw: str) -> bool:
        return "<Event" in raw and ("<System>" in raw or "<EventID>" in raw)

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return None

        event = ECSEvent().set_raw(raw)
        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

        # Try with and without namespace
        system = root.find("ns:System", ns) or root.find("System")
        if not system:
            return None

        # Extract EventID
        event_id_elem = system.find("ns:EventID", ns) or system.find("EventID")
        if event_id_elem is None:
            return None
        event_id = int(event_id_elem.text or "0")

        # Extract timestamp
        time_elem = system.find("ns:TimeCreated", ns) or system.find("TimeCreated")
        if time_elem is not None:
            ts = time_elem.get("SystemTime", "")
            if ts:
                event.set_timestamp(ts)

        # Extract computer name
        computer_elem = system.find("ns:Computer", ns) or system.find("Computer")
        if computer_elem is not None and computer_elem.text:
            event.set_host(hostname=computer_elem.text, os_type="windows")

        # Extract channel/provider
        provider_elem = system.find("ns:Provider", ns) or system.find("Provider")
        channel_elem = system.find("ns:Channel", ns) or system.find("Channel")

        provider_name = provider_elem.get("Name", "") if provider_elem is not None else ""
        channel = channel_elem.text if channel_elem is not None and channel_elem.text else ""

        # Map event ID to category/action
        mapping = WINDOWS_EVENT_MAP.get(event_id)
        if mapping:
            category, action, description = mapping
            event.set_event(module="windows", category=category, action=action)
            event.set_field("message", description)
        else:
            event.set_event(module="windows", category="unknown", action=str(event_id))

        event.set_field("winlog.event_id", event_id)
        event.set_field("winlog.provider_name", provider_name)
        event.set_field("winlog.channel", channel)

        # Extract EventData
        event_data = root.find("ns:EventData", ns) or root.find("EventData")
        if event_data is not None:
            data_dict = {}
            for data_elem in event_data:
                name = data_elem.get("Name", "")
                value = data_elem.text or ""
                if name:
                    data_dict[name] = value

            event.set_field("winlog.event_data", data_dict)

            # Extract common fields
            if "TargetUserName" in data_dict:
                event.set_user(name=data_dict["TargetUserName"],
                               domain=data_dict.get("TargetDomainName", ""))
            elif "SubjectUserName" in data_dict:
                event.set_user(name=data_dict["SubjectUserName"],
                               domain=data_dict.get("SubjectDomainName", ""))

            if "IpAddress" in data_dict and data_dict["IpAddress"] not in ("-", "::1", "127.0.0.1"):
                event.set_source(ip=data_dict["IpAddress"])
                if "IpPort" in data_dict:
                    try:
                        event.set_source(port=int(data_dict["IpPort"]))
                    except ValueError:
                        pass

            if "NewProcessName" in data_dict:
                event.set_process(
                    name=data_dict["NewProcessName"].split("\\")[-1],
                    command_line=data_dict.get("CommandLine", ""),
                )

            if "LogonType" in data_dict:
                logon_type = LOGON_TYPES.get(data_dict["LogonType"], data_dict["LogonType"])
                event.set_field("winlog.logon.type", logon_type)

        return event

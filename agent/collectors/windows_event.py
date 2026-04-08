"""
CyberNest Agent -- Windows Event Log Collector

Uses win32evtlog (pywin32) to subscribe to Security, System, Application,
PowerShell, and Sysmon channels.  Reads events since last checkpoint (stored
in a JSON state file).  Parses XML event records and maps EventID to fields.
"""

from __future__ import annotations

import asyncio
import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import BaseCollector, ecs_base_event, register_collector

# ---------------------------------------------------------------------------
# EventID -> semantic mapping (subset of common security-relevant events)
# ---------------------------------------------------------------------------
_EVENT_ID_MAP: Dict[int, Dict[str, str]] = {
    # Security channel
    4624: {"category": "authentication", "type": "start", "action": "logon_success"},
    4625: {"category": "authentication", "type": "start", "action": "logon_failure"},
    4634: {"category": "authentication", "type": "end", "action": "logoff"},
    4648: {"category": "authentication", "type": "info", "action": "explicit_logon"},
    4672: {"category": "authentication", "type": "info", "action": "special_privileges_assigned"},
    4688: {"category": "process", "type": "start", "action": "process_created"},
    4689: {"category": "process", "type": "end", "action": "process_terminated"},
    4697: {"category": "configuration", "type": "change", "action": "service_installed"},
    4698: {"category": "configuration", "type": "creation", "action": "scheduled_task_created"},
    4720: {"category": "iam", "type": "creation", "action": "user_account_created"},
    4722: {"category": "iam", "type": "change", "action": "user_account_enabled"},
    4725: {"category": "iam", "type": "change", "action": "user_account_disabled"},
    4726: {"category": "iam", "type": "deletion", "action": "user_account_deleted"},
    4732: {"category": "iam", "type": "change", "action": "member_added_to_group"},
    4738: {"category": "iam", "type": "change", "action": "user_account_changed"},
    4740: {"category": "iam", "type": "info", "action": "account_locked_out"},
    4776: {"category": "authentication", "type": "info", "action": "credential_validation"},
    5140: {"category": "file", "type": "access", "action": "network_share_accessed"},
    5156: {"category": "network", "type": "connection", "action": "connection_allowed"},
    5157: {"category": "network", "type": "connection", "action": "connection_blocked"},
    7045: {"category": "configuration", "type": "creation", "action": "service_installed"},
    # System channel
    6005: {"category": "host", "type": "start", "action": "eventlog_started"},
    6006: {"category": "host", "type": "end", "action": "eventlog_stopped"},
    6008: {"category": "host", "type": "info", "action": "unexpected_shutdown"},
    7036: {"category": "process", "type": "change", "action": "service_state_change"},
    # Sysmon
    1: {"category": "process", "type": "start", "action": "process_create"},
    3: {"category": "network", "type": "connection", "action": "network_connection"},
    7: {"category": "process", "type": "info", "action": "image_loaded"},
    8: {"category": "process", "type": "info", "action": "create_remote_thread"},
    10: {"category": "process", "type": "access", "action": "process_access"},
    11: {"category": "file", "type": "creation", "action": "file_create"},
    12: {"category": "registry", "type": "creation", "action": "registry_create_delete"},
    13: {"category": "registry", "type": "change", "action": "registry_value_set"},
    22: {"category": "network", "type": "info", "action": "dns_query"},
}

_DEFAULT_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
]

_STATE_FILENAME = "windows_event_checkpoints.json"


# ---------------------------------------------------------------------------
# XML parser helpers
# ---------------------------------------------------------------------------
def _parse_event_xml(xml_str: str) -> Dict[str, Any]:
    """Parse a Windows Event XML record into a flat dict."""
    result: Dict[str, Any] = {}
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {"raw_xml": xml_str}

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    # System section
    sys_el = root.find("e:System", ns)
    if sys_el is not None:
        eid_el = sys_el.find("e:EventID", ns)
        if eid_el is not None:
            result["event_id"] = int(eid_el.text or "0")
        provider = sys_el.find("e:Provider", ns)
        if provider is not None:
            result["provider_name"] = provider.get("Name", "")
            result["provider_guid"] = provider.get("Guid", "")
        tc = sys_el.find("e:TimeCreated", ns)
        if tc is not None:
            result["time_created"] = tc.get("SystemTime", "")
        comp = sys_el.find("e:Computer", ns)
        if comp is not None and comp.text:
            result["computer"] = comp.text
        chan = sys_el.find("e:Channel", ns)
        if chan is not None and chan.text:
            result["channel"] = chan.text
        level = sys_el.find("e:Level", ns)
        if level is not None and level.text:
            result["level"] = int(level.text)
        task_el = sys_el.find("e:Task", ns)
        if task_el is not None and task_el.text:
            result["task"] = int(task_el.text)
        record_el = sys_el.find("e:EventRecordID", ns)
        if record_el is not None and record_el.text:
            result["record_id"] = int(record_el.text)

    # EventData section
    ed = root.find("e:EventData", ns)
    if ed is not None:
        data_fields: Dict[str, str] = {}
        for child in ed:
            name = child.get("Name", "")
            value = child.text or ""
            if name:
                data_fields[name] = value
            else:
                data_fields.setdefault("_unnamed", [])  # type: ignore[arg-type]
                if isinstance(data_fields["_unnamed"], list):
                    data_fields["_unnamed"].append(value)  # type: ignore[union-attr]
        result["event_data"] = data_fields

    # UserData section (some providers use this instead)
    ud = root.find("e:UserData", ns)
    if ud is not None:
        user_fields: Dict[str, str] = {}
        for child in ud.iter():
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            if child.text and child.text.strip():
                user_fields[tag] = child.text.strip()
        if user_fields:
            result["user_data"] = user_fields

    return result


def _build_ecs_event(
    parsed: Dict[str, Any],
    channel: str,
    agent_id: str,
    hostname: str,
) -> Dict[str, Any]:
    """Convert parsed XML dict into an ECS event."""
    event_id = parsed.get("event_id", 0)
    mapping = _EVENT_ID_MAP.get(event_id, {})

    category = mapping.get("category", "host")
    evt_type = mapping.get("type", "info")
    action = mapping.get("action", f"event_{event_id}")

    event_data = parsed.get("event_data", {})

    # Build message from event data
    message_parts = [f"EventID={event_id}", f"Channel={channel}"]
    if action:
        message_parts.append(f"Action={action}")
    for key in ("TargetUserName", "SubjectUserName", "ProcessName", "CommandLine", "Image"):
        if key in event_data:
            message_parts.append(f"{key}={event_data[key]}")

    ecs = ecs_base_event(
        event_kind="event" if event_id not in (4625, 4740, 5157) else "alert",
        event_category=category,
        event_type=evt_type,
        event_dataset=f"windows.{channel.lower().replace('/', '.').replace('-', '_')}",
        agent_id=agent_id,
        agent_hostname=hostname,
        message=" | ".join(message_parts),
    )

    ecs["event"]["action"] = action
    ecs["event"]["code"] = str(event_id)
    ecs["event"]["provider"] = parsed.get("provider_name", "")

    # Map Windows-specific fields
    ecs["winlog"] = {
        "channel": channel,
        "event_id": event_id,
        "provider_name": parsed.get("provider_name", ""),
        "record_id": parsed.get("record_id", 0),
        "computer_name": parsed.get("computer", ""),
        "event_data": event_data,
    }

    # Map process fields if present
    if "ProcessId" in event_data or "ProcessName" in event_data:
        ecs["process"] = {
            "pid": int(event_data.get("ProcessId", event_data.get("NewProcessId", "0"))) if event_data.get("ProcessId", event_data.get("NewProcessId", "")).isdigit() else 0,
            "name": event_data.get("ProcessName", event_data.get("Image", "")),
            "command_line": event_data.get("CommandLine", ""),
            "executable": event_data.get("Image", event_data.get("ProcessName", "")),
        }
        if "ParentProcessId" in event_data:
            ecs["process"]["parent"] = {
                "pid": int(event_data["ParentProcessId"]) if event_data["ParentProcessId"].isdigit() else 0,
                "name": event_data.get("ParentImage", ""),
                "command_line": event_data.get("ParentCommandLine", ""),
            }

    # Map user fields
    for user_key in ("TargetUserName", "SubjectUserName"):
        if user_key in event_data:
            ecs.setdefault("user", {})
            ecs["user"]["name"] = event_data[user_key]
            domain = event_data.get(
                user_key.replace("UserName", "DomainName"), ""
            )
            if domain:
                ecs["user"]["domain"] = domain
            break

    # Map network fields (Sysmon event 3, firewall events)
    if "DestinationIp" in event_data or "DestinationAddress" in event_data:
        ecs["source"] = {
            "ip": event_data.get("SourceIp", event_data.get("SourceAddress", "")),
            "port": int(event_data.get("SourcePort", "0")) if event_data.get("SourcePort", "").isdigit() else 0,
        }
        ecs["destination"] = {
            "ip": event_data.get("DestinationIp", event_data.get("DestinationAddress", "")),
            "port": int(event_data.get("DestinationPort", "0")) if event_data.get("DestinationPort", "").isdigit() else 0,
        }
        ecs["network"] = {"protocol": event_data.get("Protocol", "")}

    return ecs


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
@register_collector("windows_event")
class WindowsEventCollector(BaseCollector):
    """Collect Windows Event Logs via win32evtlog (pywin32).

    Maintains per-channel bookmark (EventRecordID) in a JSON state file
    so it resumes where it left off across restarts.
    """

    def _state_path(self) -> Path:
        p = Path(self.config.get("state_dir", ".")) / _STATE_FILENAME
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _load_checkpoints(self) -> Dict[str, int]:
        sp = self._state_path()
        if sp.exists():
            try:
                return json.loads(sp.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_checkpoints(self, cps: Dict[str, int]) -> None:
        try:
            self._state_path().write_text(json.dumps(cps, indent=2))
        except OSError as exc:
            self.log.warning("checkpoint_save_failed", error=str(exc))

    async def _run(self) -> None:
        try:
            import win32evtlog  # type: ignore[import-untyped]
        except ImportError:
            self.log.error(
                "pywin32_not_installed",
                hint="Install pywin32: pip install pywin32",
            )
            return

        channels: List[str] = self.config.get("channels", _DEFAULT_CHANNELS)
        poll_interval: float = self.config.get("poll_interval", 1.0)
        batch_size: int = self.config.get("batch_size", 100)

        checkpoints = self._load_checkpoints()
        save_counter = 0

        self.log.info("windows_event_collector_started", channels=channels)

        # Build EvtQuery handles per channel
        handles: Dict[str, Any] = {}
        for channel in channels:
            try:
                # If we have a checkpoint, query from that record onwards
                bookmark_id = checkpoints.get(channel, 0)
                if bookmark_id > 0:
                    query = f"*[System[EventRecordID>{bookmark_id}]]"
                else:
                    query = "*"

                h = win32evtlog.EvtQuery(
                    channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                    query,
                    None,
                )
                handles[channel] = {"handle": h, "query": query}
                self.log.info(
                    "channel_opened",
                    channel=channel,
                    from_record=bookmark_id,
                )
            except Exception as exc:
                self.log.warning("channel_open_failed", channel=channel, error=str(exc))

        if not handles:
            self.log.error("no_channels_opened")
            return

        try:
            while self._running:
                events_found = False

                for channel, info in list(handles.items()):
                    try:
                        events = win32evtlog.EvtNext(
                            info["handle"], batch_size, -1, 0
                        )
                    except Exception:
                        # No more events or handle issue
                        events = []

                    for event_handle in events:
                        events_found = True
                        try:
                            xml_str = win32evtlog.EvtRender(
                                event_handle, win32evtlog.EvtRenderEventXml
                            )
                            parsed = _parse_event_xml(xml_str)
                            record_id = parsed.get("record_id", 0)

                            ecs = _build_ecs_event(
                                parsed, channel, self.agent_id, self.hostname
                            )
                            self.emit(ecs)

                            if record_id > checkpoints.get(channel, 0):
                                checkpoints[channel] = record_id
                        except Exception as exc:
                            self.log.debug(
                                "event_parse_error",
                                channel=channel,
                                error=str(exc),
                            )

                # Periodically save checkpoints
                save_counter += 1
                if save_counter >= 10:
                    self._save_checkpoints(checkpoints)
                    save_counter = 0

                if not events_found:
                    await asyncio.sleep(poll_interval)
                else:
                    # Yield to event loop but come back quickly
                    await asyncio.sleep(0.05)
        finally:
            self._save_checkpoints(checkpoints)
            for info in handles.values():
                try:
                    win32evtlog.EvtClose(info["handle"])
                except Exception:
                    pass

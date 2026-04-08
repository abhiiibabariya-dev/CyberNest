"""
CyberNest Agent -- macOS Unified Log Collector

Uses subprocess to run ``log stream --style json`` and parses the JSON output
lines.  Filters by configured subsystems.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from . import BaseCollector, ecs_base_event, register_collector

_CATEGORY_MAP = {
    "com.apple.authd": "authentication",
    "com.apple.securityd": "authentication",
    "com.apple.opendirectoryd": "authentication",
    "com.apple.kernel": "host",
    "com.apple.launchd": "process",
    "com.apple.xpc": "process",
    "com.apple.networkd": "network",
    "com.apple.symptomsd": "network",
    "com.apple.CoreWLAN": "network",
    "com.apple.ftp": "network",
}


def _map_category(subsystem: str) -> str:
    """Map an Apple subsystem string to an ECS event.category."""
    for prefix, cat in _CATEGORY_MAP.items():
        if subsystem.startswith(prefix):
            return cat
    return "host"


def _map_log_type(log_type: str) -> str:
    """Map macOS log type to ECS event.kind."""
    lt = log_type.lower()
    if lt in ("error", "fault"):
        return "alert"
    return "event"


@register_collector("macos_log")
class MacOSLogCollector(BaseCollector):
    """Stream macOS unified logs via ``log stream --style json``."""

    async def _run(self) -> None:
        if not shutil.which("log"):
            self.log.error("macos_log_binary_not_found", hint="This collector requires macOS")
            return

        subsystems: List[str] = self.config.get("subsystems", [])
        log_levels: List[str] = self.config.get("levels", ["default", "info", "debug"])
        predicate: str = self.config.get("predicate", "")

        # Build command
        cmd = ["log", "stream", "--style", "json"]
        if predicate:
            cmd.extend(["--predicate", predicate])
        elif subsystems:
            # Build a compound predicate from subsystems
            parts = [f'subsystem == "{s}"' for s in subsystems]
            compound = " OR ".join(parts)
            cmd.extend(["--predicate", compound])
        if log_levels:
            cmd.extend(["--level", log_levels[0]])

        self.log.info("macos_log_stream_starting", cmd=" ".join(cmd))

        process: Optional[asyncio.subprocess.Process] = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            assert process.stdout is not None
            buffer = b""

            while self._running:
                try:
                    chunk = await asyncio.wait_for(
                        process.stdout.read(8192), timeout=5.0
                    )
                except asyncio.TimeoutError:
                    continue

                if not chunk:
                    # Process exited
                    self.log.warning("macos_log_stream_ended")
                    break

                buffer += chunk
                while b"\n" in buffer:
                    line_bytes, buffer = buffer.split(b"\n", 1)
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    # The first line from `log stream` is a header, skip it
                    if line.startswith("Filtering the log data"):
                        continue

                    evt = self._parse_json_line(line)
                    if evt:
                        self.emit(evt)

        finally:
            if process and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    process.kill()

    def _parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single JSON log line from ``log stream``."""
        # macOS log stream outputs an array-like syntax; individual entries
        # are JSON objects separated by commas
        line = line.strip().rstrip(",")
        if line.startswith("["):
            line = line[1:]
        if line.endswith("]"):
            line = line[:-1]
        line = line.strip()
        if not line or not line.startswith("{"):
            return None

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None

        subsystem = obj.get("subsystem", "")
        category_str = obj.get("category", "")
        log_type = obj.get("messageType", "Default")
        message = obj.get("eventMessage", "")
        process_name = obj.get("processImagePath", "").rsplit("/", 1)[-1]
        pid = obj.get("processID", 0)
        timestamp = obj.get("timestamp", "")
        sender = obj.get("senderImagePath", "")

        ecs = ecs_base_event(
            event_kind=_map_log_type(log_type),
            event_category=_map_category(subsystem),
            event_type="info",
            event_dataset=f"macos.{subsystem}" if subsystem else "macos.unified_log",
            agent_id=self.agent_id,
            agent_hostname=self.hostname,
            message=message,
        )

        ecs["log"] = {
            "level": log_type.lower(),
            "logger": subsystem,
        }
        ecs["process"] = {
            "name": process_name,
            "pid": pid,
            "executable": obj.get("processImagePath", ""),
        }
        ecs["macos"] = {
            "subsystem": subsystem,
            "category": category_str,
            "sender": sender,
            "activity_id": obj.get("activityIdentifier", 0),
            "thread_id": obj.get("threadID", 0),
            "trace_id": obj.get("traceID", ""),
            "message_type": log_type,
        }

        if timestamp:
            ecs["@timestamp"] = timestamp

        return ecs

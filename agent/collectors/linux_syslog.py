"""
CyberNest Agent -- Linux Syslog Collector

Uses watchdog FileSystemEventHandler to tail /var/log/syslog, auth.log,
kern.log, messages, and secure.  Detects log rotation via inode change and
parses syslog lines into structured ECS events.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from . import BaseCollector, ecs_base_event, register_collector

# ---------------------------------------------------------------------------
# Syslog line parser  (RFC 3164 style)
# ---------------------------------------------------------------------------
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)"
)

_PRIORITY_MAP = {
    "auth": "authentication",
    "authpriv": "authentication",
    "kern": "host",
    "daemon": "process",
    "syslog": "host",
}


def _parse_syslog_line(line: str, source_path: str) -> Optional[Dict[str, Any]]:
    """Parse a single syslog line into an ECS-ish dict, or None."""
    line = line.rstrip("\n\r")
    if not line:
        return None

    m = _SYSLOG_RE.match(line)
    if not m:
        # Unparseable -- still emit raw
        return {
            "message": line,
            "event": {
                "kind": "event",
                "category": "host",
                "type": "info",
                "dataset": "syslog",
                "original": line,
            },
            "log": {"file": {"path": source_path}},
        }

    ts_str = m.group("timestamp")
    # Syslog timestamps lack year; assume current year
    year = datetime.now().year
    try:
        ts = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        ts = datetime.now(timezone.utc)

    program = (m.group("program") or "").strip()
    category = "host"
    for prefix, cat in _PRIORITY_MAP.items():
        if prefix in source_path.lower() or prefix in program.lower():
            category = cat
            break

    return {
        "@timestamp": ts.isoformat(),
        "message": m.group("message"),
        "event": {
            "kind": "event",
            "category": category,
            "type": "info",
            "dataset": "syslog",
            "original": line,
        },
        "host": {"hostname": m.group("hostname")},
        "process": {
            "name": program,
            "pid": int(m.group("pid")) if m.group("pid") else None,
        },
        "log": {"file": {"path": source_path}, "syslog": {"facility": program}},
    }


# ---------------------------------------------------------------------------
# Watchdog handler for log file changes
# ---------------------------------------------------------------------------
class _LogTailHandler(FileSystemEventHandler):
    """Receives filesystem events and sets an asyncio Event for the collector."""

    def __init__(self, notify: asyncio.Event, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._notify = notify
        self._loop = loop

    def on_modified(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._loop.call_soon_threadsafe(self._notify.set)


# ---------------------------------------------------------------------------
# Tail state per file -- handles rotation via inode
# ---------------------------------------------------------------------------
class _FileTailState:
    __slots__ = ("path", "offset", "inode")

    def __init__(self, path: str) -> None:
        self.path = path
        self.offset: int = 0
        self.inode: int = 0
        self._init_position()

    def _init_position(self) -> None:
        try:
            stat = os.stat(self.path)
            self.inode = stat.st_ino
            self.offset = stat.st_size  # start at end on first run
        except OSError:
            pass

    def rotated(self) -> bool:
        """Return True if the file's inode changed (log rotation)."""
        try:
            return os.stat(self.path).st_ino != self.inode
        except OSError:
            return False

    def read_new_lines(self) -> List[str]:
        """Read new lines since last offset. Handles rotation."""
        try:
            stat = os.stat(self.path)
        except OSError:
            return []

        current_inode = stat.st_ino
        current_size = stat.st_size

        # Detect rotation: inode changed or file shrank
        if current_inode != self.inode or current_size < self.offset:
            self.inode = current_inode
            self.offset = 0

        if current_size <= self.offset:
            return []

        lines: List[str] = []
        try:
            with open(self.path, "r", errors="replace") as fh:
                fh.seek(self.offset)
                lines = fh.readlines()
                self.offset = fh.tell()
        except (OSError, PermissionError):
            pass
        return lines


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------
_DEFAULT_PATHS = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/messages",
    "/var/log/secure",
]


@register_collector("linux_syslog")
class LinuxSyslogCollector(BaseCollector):
    """Tail Linux syslog files using watchdog + inode-based rotation detection."""

    async def _run(self) -> None:
        paths: List[str] = self.config.get("paths", _DEFAULT_PATHS)
        poll_fallback: float = self.config.get("poll_interval", 1.0)

        # Filter to files that actually exist
        active_paths = [p for p in paths if Path(p).exists()]
        if not active_paths:
            self.log.warning("no_syslog_files_found", configured=paths)
            # Keep retrying in case paths appear later
            while self._running:
                await asyncio.sleep(10)
                active_paths = [p for p in paths if Path(p).exists()]
                if active_paths:
                    break
            if not self._running:
                return

        # Build tail states
        tails = {p: _FileTailState(p) for p in active_paths}

        # Setup watchdog observer
        loop = asyncio.get_running_loop()
        notify = asyncio.Event()
        handler = _LogTailHandler(notify, loop)
        observer = Observer()

        watched_dirs: set[str] = set()
        for p in active_paths:
            d = str(Path(p).parent)
            if d not in watched_dirs:
                observer.schedule(handler, d, recursive=False)
                watched_dirs.add(d)

        observer.start()
        self.log.info("watching_syslog_files", paths=active_paths)

        try:
            while self._running:
                # Wait for either a file change notification or a timeout
                try:
                    await asyncio.wait_for(notify.wait(), timeout=poll_fallback)
                except asyncio.TimeoutError:
                    pass
                notify.clear()

                # Check all tailed files
                for path_str, tail in tails.items():
                    new_lines = tail.read_new_lines()
                    for line in new_lines:
                        parsed = _parse_syslog_line(line, path_str)
                        if parsed:
                            evt = ecs_base_event(
                                event_kind="event",
                                event_category=parsed.get("event", {}).get(
                                    "category", "host"
                                ),
                                event_type="info",
                                event_dataset="syslog",
                                agent_id=self.agent_id,
                                agent_hostname=self.hostname,
                                message=parsed.get("message", ""),
                                extra=parsed,
                            )
                            self.emit(evt)

                # Check for new files that may have appeared
                for p in paths:
                    if p not in tails and Path(p).exists():
                        tails[p] = _FileTailState(p)
                        d = str(Path(p).parent)
                        if d not in watched_dirs:
                            observer.schedule(handler, d, recursive=False)
                            watched_dirs.add(d)
                        self.log.info("new_syslog_file_detected", path=p)
        finally:
            observer.stop()
            observer.join(timeout=5)

"""
CyberNest Agent -- Process Monitor Collector

Polls psutil.process_iter() every N seconds.  Detects new processes by
comparing against a previous snapshot.  Records pid, name, cmdline, ppid,
parent_name, username, exe path, create_time.  Calculates SHA-256 of
executable on first seen.  Flags execution from temp directories.
"""

from __future__ import annotations

import asyncio
import os
import platform
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

import psutil

from . import BaseCollector, ecs_base_event, register_collector

# Directories commonly used by malware / staging
_TEMP_DIRS: Set[str] = set()


def _init_temp_dirs() -> None:
    """Build a set of known temporary directories (normalised, lowercase)."""
    global _TEMP_DIRS
    candidates = [
        tempfile.gettempdir(),
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        "/tmp",
        "/var/tmp",
        "/dev/shm",
    ]
    if platform.system() == "Windows":
        candidates.extend([
            os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp"),
            r"C:\Windows\Temp",
        ])
    _TEMP_DIRS = {os.path.normpath(p).lower() for p in candidates if p}


_init_temp_dirs()


def _is_temp_path(exe: str) -> bool:
    """Check if an executable path resides inside a temp directory."""
    norm = os.path.normpath(exe).lower()
    for td in _TEMP_DIRS:
        if norm.startswith(td):
            return True
    return False


def _get_proc_info(proc: psutil.Process) -> Optional[Dict[str, Any]]:
    """Safely extract all interesting fields from a psutil.Process."""
    try:
        with proc.oneshot():
            info: Dict[str, Any] = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": "",
                "cmdline": [],
                "username": "",
                "ppid": 0,
                "parent_name": "",
                "create_time": 0.0,
                "status": "",
            }
            try:
                info["exe"] = proc.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                info["cmdline"] = proc.cmdline()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                info["username"] = proc.username()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                info["ppid"] = proc.ppid()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                parent = proc.parent()
                if parent:
                    info["parent_name"] = parent.name()
            except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess, OSError):
                pass
            try:
                info["create_time"] = proc.create_time()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                info["status"] = proc.status()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            return info
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


@register_collector("process_monitor")
class ProcessMonitorCollector(BaseCollector):
    """Detect new processes by polling psutil at a configurable interval."""

    async def _run(self) -> None:
        interval: float = self.config.get("interval", 5.0)
        hash_executables: bool = self.config.get("hash_executables", True)
        max_hash_size: int = self.config.get("max_hash_size_mb", 50) * 1024 * 1024

        # pid -> create_time acts as a unique key (PIDs recycle)
        known_processes: Dict[int, float] = {}
        # exe path -> sha256  (cache so we don't re-hash the same binary)
        exe_hash_cache: Dict[str, str] = {}

        # Snapshot current processes on first run (don't alert on them)
        for proc in psutil.process_iter():
            try:
                known_processes[proc.pid] = proc.create_time()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        self.log.info(
            "process_monitor_started",
            interval=interval,
            initial_processes=len(known_processes),
        )

        while self._running:
            await asyncio.sleep(interval)

            current_snapshot: Dict[int, float] = {}

            for proc in psutil.process_iter():
                try:
                    pid = proc.pid
                    ctime = proc.create_time()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                current_snapshot[pid] = ctime

                # Is this a new process?
                prev_ctime = known_processes.get(pid)
                if prev_ctime is not None and prev_ctime == ctime:
                    continue  # Known process, same incarnation

                # New process detected
                info = _get_proc_info(proc)
                if info is None:
                    continue

                # Hash executable on first see
                exe_hash = ""
                exe_path = info.get("exe", "")
                if hash_executables and exe_path:
                    if exe_path in exe_hash_cache:
                        exe_hash = exe_hash_cache[exe_path]
                    else:
                        try:
                            if os.path.isfile(exe_path) and os.path.getsize(exe_path) <= max_hash_size:
                                exe_hash = self.sha256_file(exe_path)
                                exe_hash_cache[exe_path] = exe_hash
                        except OSError:
                            pass

                # Flag suspicious traits
                alerts = []
                if exe_path and _is_temp_path(exe_path):
                    alerts.append("execution_from_temp_dir")

                cmdline_str = " ".join(info.get("cmdline") or [])

                # Build ECS event
                kind = "alert" if alerts else "event"
                ecs = ecs_base_event(
                    event_kind=kind,
                    event_category="process",
                    event_type="start",
                    event_dataset="process_monitor",
                    agent_id=self.agent_id,
                    agent_hostname=self.hostname,
                    message=f"New process: {info['name']} (PID {info['pid']}) by {info.get('username', 'unknown')}",
                )

                ecs["event"]["action"] = "process_started"
                ecs["process"] = {
                    "pid": info["pid"],
                    "name": info["name"],
                    "executable": exe_path,
                    "command_line": cmdline_str,
                    "args": info.get("cmdline", []),
                    "working_directory": "",
                    "start": datetime.fromtimestamp(
                        info["create_time"], tz=timezone.utc
                    ).isoformat()
                    if info["create_time"]
                    else "",
                    "parent": {
                        "pid": info["ppid"],
                        "name": info["parent_name"],
                    },
                }
                if exe_hash:
                    ecs["process"]["hash"] = {"sha256": exe_hash}

                ecs["user"] = {"name": info.get("username", "")}

                if alerts:
                    ecs["cybernest"] = {"alerts": alerts}

                self.emit(ecs)

            # Update snapshot
            known_processes = current_snapshot

            # Prune exe hash cache if it grows too large
            if len(exe_hash_cache) > 5000:
                # Keep the 2000 most recent entries (arbitrary trim)
                items = list(exe_hash_cache.items())
                exe_hash_cache = dict(items[-2000:])

"""
CyberNest Agent -- File Integrity Monitoring (FIM) Collector

Uses watchdog Observer on configured paths.  Emits ECS file integrity events
for created, modified, deleted, and moved files.  On create/modify calculates
SHA-256 hash.  Excludes files matching configured patterns.
"""

from __future__ import annotations

import asyncio
import fnmatch
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    DirCreatedEvent,
    DirDeletedEvent,
    DirMovedEvent,
)

from . import BaseCollector, ecs_base_event, register_collector


class _FIMEventHandler(FileSystemEventHandler):
    """Watchdog handler that queues FIM events for the collector."""

    def __init__(
        self,
        queue: asyncio.Queue,  # type: ignore[type-arg]
        loop: asyncio.AbstractEventLoop,
        excludes: List[str],
    ) -> None:
        super().__init__()
        self._queue = queue
        self._loop = loop
        self._excludes = excludes

    def _is_excluded(self, path: str) -> bool:
        basename = os.path.basename(path)
        for pattern in self._excludes:
            if fnmatch.fnmatch(basename, pattern):
                return True
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def _enqueue(self, action: str, src_path: str, dest_path: str = "") -> None:
        if self._is_excluded(src_path):
            return
        if dest_path and self._is_excluded(dest_path):
            return
        evt = {
            "action": action,
            "src_path": src_path,
            "dest_path": dest_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._loop.call_soon_threadsafe(self._queue.put_nowait, evt)

    def on_created(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._enqueue("created", event.src_path)

    def on_modified(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._enqueue("modified", event.src_path)

    def on_deleted(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._enqueue("deleted", event.src_path)

    def on_moved(self, event):  # type: ignore[override]
        if not event.is_directory:
            self._enqueue("moved", event.src_path, event.dest_path)


def _file_metadata(path: str) -> Dict[str, Any]:
    """Gather metadata about a file (best-effort)."""
    meta: Dict[str, Any] = {"path": path, "name": os.path.basename(path)}
    try:
        st = os.stat(path)
        meta["size"] = st.st_size
        meta["mtime"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        meta["ctime"] = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
        meta["inode"] = st.st_ino
        meta["mode"] = oct(st.st_mode)
        try:
            meta["owner_uid"] = st.st_uid
            meta["group_gid"] = st.st_gid
        except AttributeError:
            pass  # Windows
        meta["extension"] = Path(path).suffix.lstrip(".")
        meta["directory"] = str(Path(path).parent)
    except (OSError, PermissionError):
        pass
    return meta


@register_collector("fim")
class FIMCollector(BaseCollector):
    """Real-time file integrity monitoring via watchdog."""

    async def _run(self) -> None:
        paths: List[str] = self.config.get("paths", [])
        excludes: List[str] = self.config.get("excludes", ["*.tmp", "*.swp", "*.log", "~*"])
        recursive: bool = self.config.get("recursive", True)
        hash_on_change: bool = self.config.get("hash_on_change", True)
        max_hash_size: int = self.config.get("max_hash_size_mb", 100) * 1024 * 1024

        if not paths:
            self.log.warning("fim_no_paths_configured")
            return

        loop = asyncio.get_running_loop()
        event_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=5000)

        handler = _FIMEventHandler(event_queue, loop, excludes)
        observer = Observer()

        # Track known file hashes for change detection
        known_hashes: Dict[str, str] = {}

        active_watches = 0
        for watch_path in paths:
            if not Path(watch_path).exists():
                self.log.warning("fim_path_not_found", path=watch_path)
                continue
            try:
                observer.schedule(handler, watch_path, recursive=recursive)
                active_watches += 1
                self.log.info("fim_watching", path=watch_path, recursive=recursive)
            except Exception as exc:
                self.log.warning("fim_watch_failed", path=watch_path, error=str(exc))

        if active_watches == 0:
            self.log.error("fim_no_valid_paths")
            return

        observer.start()
        self.log.info("fim_observer_started", watches=active_watches)

        try:
            while self._running:
                # Drain events from the queue
                try:
                    raw_evt = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                action = raw_evt["action"]
                src_path = raw_evt["src_path"]
                dest_path = raw_evt.get("dest_path", "")

                # Build file metadata
                file_info = _file_metadata(src_path)

                # Compute hash on create / modify
                file_hash = ""
                if hash_on_change and action in ("created", "modified"):
                    try:
                        size = os.path.getsize(src_path)
                        if size <= max_hash_size:
                            file_hash = self.sha256_file(src_path)
                    except OSError:
                        pass

                # Detect actual content change vs. metadata-only touch
                if action == "modified" and file_hash:
                    prev_hash = known_hashes.get(src_path)
                    if prev_hash == file_hash:
                        continue  # No actual content change
                    known_hashes[src_path] = file_hash
                elif action == "created" and file_hash:
                    known_hashes[src_path] = file_hash
                elif action == "deleted":
                    known_hashes.pop(src_path, None)

                # Build ECS event
                ecs = ecs_base_event(
                    event_kind="event",
                    event_category="file",
                    event_type={
                        "created": "creation",
                        "modified": "change",
                        "deleted": "deletion",
                        "moved": "change",
                    }.get(action, "info"),
                    event_dataset="fim",
                    agent_id=self.agent_id,
                    agent_hostname=self.hostname,
                    message=f"File {action}: {src_path}",
                )

                ecs["event"]["action"] = action
                ecs["file"] = file_info
                if file_hash:
                    ecs["file"]["hash"] = {"sha256": file_hash}

                if action == "moved" and dest_path:
                    ecs["file"]["target_path"] = dest_path
                    dest_info = _file_metadata(dest_path)
                    ecs["file"]["target"] = dest_info
                    if hash_on_change:
                        dest_hash = self.sha256_file(dest_path)
                        if dest_hash:
                            ecs["file"]["target"]["hash"] = {"sha256": dest_hash}
                            known_hashes[dest_path] = dest_hash

                self.emit(ecs)

        finally:
            observer.stop()
            observer.join(timeout=5)

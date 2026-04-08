"""
CyberNest Agent Collectors -- Base class and registry for all event collectors.
"""

from __future__ import annotations

import abc
import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Type

import structlog

logger = structlog.get_logger("cybernest.collectors")

# ---------------------------------------------------------------------------
# Global collector registry
# ---------------------------------------------------------------------------
_REGISTRY: Dict[str, Type["BaseCollector"]] = {}


def register_collector(name: str):
    """Class decorator that registers a collector under *name*."""

    def decorator(cls: Type[BaseCollector]) -> Type[BaseCollector]:
        _REGISTRY[name] = cls
        return cls

    return decorator


def get_collector(name: str) -> Optional[Type["BaseCollector"]]:
    return _REGISTRY.get(name)


def list_collectors() -> List[str]:
    return list(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# ECS event helper
# ---------------------------------------------------------------------------
def ecs_base_event(
    *,
    event_kind: str = "event",
    event_category: str = "host",
    event_type: str = "info",
    event_dataset: str = "",
    agent_id: str = "",
    agent_hostname: str = "",
    message: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a minimal Elastic Common Schema (ECS) event dict."""
    now = datetime.now(timezone.utc)
    evt: Dict[str, Any] = {
        "@timestamp": now.isoformat(),
        "event": {
            "kind": event_kind,
            "category": event_category,
            "type": event_type,
            "dataset": event_dataset,
            "created": now.isoformat(),
        },
        "agent": {
            "id": agent_id,
            "hostname": agent_hostname,
            "type": "cybernest-agent",
        },
        "message": message,
    }
    if extra:
        evt.update(extra)
    return evt


# ---------------------------------------------------------------------------
# Base collector
# ---------------------------------------------------------------------------
class BaseCollector(abc.ABC):
    """Abstract base for every CyberNest collector.

    Subclasses must implement ``_run`` which should loop and call
    ``self.emit(event_dict)`` for every collected event.
    """

    def __init__(
        self,
        *,
        name: str,
        config: Dict[str, Any],
        agent_id: str = "",
        hostname: str = "",
        emit_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.name = name
        self.config = config
        self.agent_id = agent_id
        self.hostname = hostname
        self._emit_fn = emit_fn
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self.log = structlog.get_logger("cybernest.collector").bind(collector=name)

    # -- public API ----------------------------------------------------------

    async def start(self) -> asyncio.Task:
        """Start the collector as a background asyncio task."""
        self._running = True
        self._task = asyncio.create_task(self._safe_run(), name=f"collector-{self.name}")
        self.log.info("collector_started")
        return self._task

    async def stop(self) -> None:
        """Signal the collector to stop and wait for it."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.log.info("collector_stopped")

    @property
    def running(self) -> bool:
        return self._running

    def emit(self, event: Dict[str, Any]) -> None:
        """Push an event to the agent's queue via the callback."""
        if "agent" not in event:
            event["agent"] = {"id": self.agent_id, "hostname": self.hostname}
        if "@timestamp" not in event:
            event["@timestamp"] = datetime.now(timezone.utc).isoformat()
        if self._emit_fn:
            self._emit_fn(event)
        else:
            self.log.warning("emit_fn_not_set", event_keys=list(event.keys()))

    # -- internals -----------------------------------------------------------

    async def _safe_run(self) -> None:
        """Wrap _run with crash resilience."""
        backoff = 1.0
        while self._running:
            try:
                await self._run()
            except asyncio.CancelledError:
                break
            except Exception:
                self.log.exception("collector_crash", backoff=backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
            else:
                break  # clean exit from _run

    @abc.abstractmethod
    async def _run(self) -> None:
        """Main collector loop -- implemented by subclasses."""
        ...

    # -- helpers available to subclasses ------------------------------------

    @staticmethod
    def sha256_file(path: str, chunk_size: int = 65536) -> str:
        """Return hex SHA-256 of a file, or empty string on error."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return ""

    @staticmethod
    def sha256_string(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()

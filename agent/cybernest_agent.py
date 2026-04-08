#!/usr/bin/env python3
"""
CyberNest Agent -- Main entry point

Cross-platform SIEM agent that:
  - Loads config from cybernest-agent.yml (or --config flag)
  - Auto-enrolls with the CyberNest Manager on first run
  - Starts OS-appropriate collectors as asyncio tasks
  - Deduplicates events via SHA-256 LRU cache (1000 entries)
  - Forwards events over TLS WebSocket with batching and offline buffer
  - Handles commands from the manager (isolate, unisolate, etc.)
  - Reports self-health (CPU / memory) in heartbeats
  - Shuts down gracefully on SIGTERM / SIGINT
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import aiohttp
import psutil
import structlog
import yaml

# -- CyberNest imports -------------------------------------------------------
from agent.collectors import (
    BaseCollector,
    get_collector,
    list_collectors,
    register_collector,
)
from agent.forwarder.tls_forwarder import TLSForwarder

# Force-import all collector modules so they register themselves
import agent.collectors.linux_syslog  # noqa: F401
import agent.collectors.windows_event  # noqa: F401
import agent.collectors.macos_log  # noqa: F401
import agent.collectors.fim  # noqa: F401
import agent.collectors.process_monitor  # noqa: F401
import agent.collectors.network_monitor  # noqa: F401
import agent.collectors.registry_monitor  # noqa: F401

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AGENT_VERSION = "1.0.0"
DEFAULT_CONFIG = Path(__file__).parent / "cybernest-agent.yml"
DEFAULT_STATE_DIR = Path(__file__).parent / "data"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger("cybernest.agent")


# ---------------------------------------------------------------------------
# SHA-256 LRU dedup cache
# ---------------------------------------------------------------------------
class LRUDedup:
    """LRU cache that stores SHA-256 hashes to deduplicate events."""

    def __init__(self, maxsize: int = 1000) -> None:
        self._cache: OrderedDict[str, None] = OrderedDict()
        self._maxsize = maxsize

    def is_duplicate(self, event_str: str) -> bool:
        """Return True if event_str has been seen recently."""
        h = hashlib.sha256(event_str.encode("utf-8", errors="replace")).hexdigest()
        if h in self._cache:
            self._cache.move_to_end(h)
            return True
        self._cache[h] = None
        if len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)
        return False


# ---------------------------------------------------------------------------
# Agent state (persisted to disk)
# ---------------------------------------------------------------------------
class AgentState:
    """Persistent agent state stored as JSON."""

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "agent_state.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.agent_id: str = ""
        self.api_key: str = ""
        self.hostname: str = platform.node()
        self.os_type: str = platform.system().lower()
        self.os_version: str = platform.version()
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                self.agent_id = data.get("agent_id", "")
                self.api_key = data.get("api_key", "")
            except (json.JSONDecodeError, OSError):
                pass

    def save(self) -> None:
        self._path.write_text(
            json.dumps(
                {
                    "agent_id": self.agent_id,
                    "api_key": self.api_key,
                    "hostname": self.hostname,
                    "os_type": self.os_type,
                    "os_version": self.os_version,
                    "agent_version": AGENT_VERSION,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            )
        )

    @property
    def enrolled(self) -> bool:
        return bool(self.agent_id and self.api_key)


# ---------------------------------------------------------------------------
# Helper: primary IP
# ---------------------------------------------------------------------------
def _get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# OS-specific command handlers
# ---------------------------------------------------------------------------
def _isolate_host() -> Dict[str, Any]:
    """Block all network except manager connection."""
    system = platform.system()
    try:
        if system == "Linux":
            cmds = [
                ["iptables", "-F"],
                ["iptables", "-P", "INPUT", "DROP"],
                ["iptables", "-P", "OUTPUT", "DROP"],
                ["iptables", "-P", "FORWARD", "DROP"],
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            return {"status": "isolated", "method": "iptables"}

        elif system == "Windows":
            cmds = [
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"],
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=CyberNest-Allow-Loopback", "dir=in", "action=allow", "remoteip=127.0.0.1"],
                ["netsh", "advfirewall", "firewall", "add", "rule", "name=CyberNest-Allow-Loopback-Out", "dir=out", "action=allow", "remoteip=127.0.0.1"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            return {"status": "isolated", "method": "netsh"}

        elif system == "Darwin":
            pf_rules = "block all\npass on lo0 all\n"
            pf_path = "/tmp/cybernest_pf.conf"
            Path(pf_path).write_text(pf_rules)
            subprocess.run(["pfctl", "-f", pf_path, "-e"], check=True, capture_output=True, timeout=10)
            return {"status": "isolated", "method": "pfctl"}

        return {"status": "error", "message": f"Unsupported OS: {system}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _unisolate_host() -> Dict[str, Any]:
    """Remove network isolation."""
    system = platform.system()
    try:
        if system == "Linux":
            cmds = [
                ["iptables", "-F"],
                ["iptables", "-P", "INPUT", "ACCEPT"],
                ["iptables", "-P", "OUTPUT", "ACCEPT"],
                ["iptables", "-P", "FORWARD", "ACCEPT"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            return {"status": "unisolated", "method": "iptables"}

        elif system == "Windows":
            cmds = [
                ["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"],
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=CyberNest-Allow-Loopback"],
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=CyberNest-Allow-Loopback-Out"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=10)
            return {"status": "unisolated", "method": "netsh"}

        elif system == "Darwin":
            subprocess.run(["pfctl", "-d"], capture_output=True, timeout=10)
            return {"status": "unisolated", "method": "pfctl"}

        return {"status": "error", "message": f"Unsupported OS: {system}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def _get_processes() -> Dict[str, Any]:
    """Return current process list."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time", "cpu_percent", "memory_percent"]):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "username": info.get("username", ""),
                "cmdline": " ".join(info.get("cmdline") or []),
                "create_time": info.get("create_time", 0),
                "cpu_percent": info.get("cpu_percent", 0),
                "memory_percent": round(info.get("memory_percent", 0), 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return {"processes": procs, "count": len(procs)}


def _get_connections() -> Dict[str, Any]:
    """Return current network connections."""
    conns = []
    try:
        for conn in psutil.net_connections(kind="inet"):
            entry: Dict[str, Any] = {
                "status": conn.status,
                "pid": conn.pid,
                "family": "ipv4" if conn.family == 2 else "ipv6",
                "type": "tcp" if conn.type == 1 else "udp",
            }
            if conn.laddr:
                entry["local_ip"] = conn.laddr.ip
                entry["local_port"] = conn.laddr.port
            if conn.raddr:
                entry["remote_ip"] = conn.raddr.ip
                entry["remote_port"] = conn.raddr.port
            # Resolve process name
            if conn.pid:
                try:
                    entry["process_name"] = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    entry["process_name"] = ""
            conns.append(entry)
    except (psutil.AccessDenied, OSError):
        pass
    return {"connections": conns, "count": len(conns)}


# ---------------------------------------------------------------------------
# Main Agent class
# ---------------------------------------------------------------------------
class CyberNestAgent:
    """Production CyberNest SIEM agent."""

    def __init__(self, config_path: str) -> None:
        with open(config_path, "r") as fh:
            self.config: Dict[str, Any] = yaml.safe_load(fh) or {}

        state_dir = Path(
            self.config.get("agent", {}).get("state_dir", str(DEFAULT_STATE_DIR))
        )
        self.state = AgentState(state_dir)

        # Override api_key from config if present
        cfg_key = self.config.get("manager", {}).get("api_key", "")
        if cfg_key:
            self.state.api_key = cfg_key

        # Manager URL
        mgr = self.config.get("manager", {})
        proto = "wss" if mgr.get("tls", {}).get("enabled", True) else "ws"
        host = mgr.get("host", "localhost")
        port = mgr.get("port", 8443)
        self._manager_ws_url = f"{proto}://{host}:{port}"
        self._manager_http_url = (
            f"{'https' if proto == 'wss' else 'http'}://{host}:{port}"
        )

        # Dedup
        self._dedup = LRUDedup(maxsize=self.config.get("agent", {}).get("dedup_cache_size", 1000))

        # Logging config
        log_level = self.config.get("logging", {}).get("level", "INFO").upper()
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(
                {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}.get(log_level, 20)
            ),
        )

        # Forwarder config
        fwd_cfg = self.config.get("forwarder", {})
        tls_cfg = mgr.get("tls", {})
        self._forwarder = TLSForwarder(
            manager_url=self._manager_ws_url,
            api_key=self.state.api_key,
            agent_id=self.state.agent_id,
            ca_cert=tls_cfg.get("ca_cert", ""),
            client_cert=tls_cfg.get("client_cert", ""),
            client_key=tls_cfg.get("client_key", ""),
            verify_ssl=tls_cfg.get("verify", True),
            batch_size=fwd_cfg.get("batch_size", 50),
            flush_interval=fwd_cfg.get("flush_interval", 1.0),
            queue_maxsize=fwd_cfg.get("queue_maxsize", 10000),
            buffer_file=str(state_dir / fwd_cfg.get("buffer_file", "event_buffer.jsonl")),
            reconnect_base=fwd_cfg.get("reconnect_base", 1.0),
            reconnect_max=fwd_cfg.get("reconnect_max", 60.0),
            heartbeat_interval=fwd_cfg.get("heartbeat_interval", 30.0),
            command_handler=self._handle_command,
            health_fn=self._get_health,
        )

        self._collectors: List[BaseCollector] = []
        self._running = False
        self._tasks: List[asyncio.Task] = []

    # ------------------------------------------------------------------
    # Auto-enrollment
    # ------------------------------------------------------------------

    async def _enroll(self) -> None:
        """Register with CyberNest Manager if not already enrolled."""
        if self.state.enrolled:
            logger.info("already_enrolled", agent_id=self.state.agent_id)
            return

        url = f"{self._manager_http_url}/api/v1/agents/register"
        tls_cfg = self.config.get("manager", {}).get("tls", {})
        verify = tls_cfg.get("verify", True)

        payload = {
            "hostname": self.state.hostname,
            "ip_address": _get_primary_ip(),
            "os_type": self.state.os_type,
            "os_version": self.state.os_version,
            "agent_version": AGENT_VERSION,
            "labels": self.config.get("agent", {}).get("labels", {}),
            "group": self.config.get("agent", {}).get("group", "default"),
            "capabilities": list_collectors(),
        }

        ssl_ctx = None
        if not verify:
            import ssl as _ssl

            ssl_ctx = _ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE

        backoff = 2.0
        for attempt in range(10):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url, json=payload, ssl=ssl_ctx if not verify else None
                    ) as resp:
                        if resp.status in (200, 201):
                            data = await resp.json()
                            self.state.agent_id = data.get("agent_id", data.get("id", ""))
                            self.state.api_key = data.get("api_key", data.get("token", ""))
                            self.state.save()
                            logger.info(
                                "enrolled",
                                agent_id=self.state.agent_id,
                            )
                            # Update forwarder with new credentials
                            self._forwarder._agent_id = self.state.agent_id
                            self._forwarder._api_key = self.state.api_key
                            return
                        else:
                            body = await resp.text()
                            logger.warning(
                                "enrollment_failed",
                                status=resp.status,
                                body=body[:500],
                                attempt=attempt + 1,
                            )
            except Exception as exc:
                logger.warning(
                    "enrollment_error",
                    error=str(exc),
                    attempt=attempt + 1,
                    backoff=backoff,
                )

            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60.0)

        logger.error("enrollment_exhausted", attempts=10)

    # ------------------------------------------------------------------
    # Event emission (called by collectors)
    # ------------------------------------------------------------------

    def _emit_event(self, event: Dict[str, Any]) -> None:
        """Deduplicate and enqueue an event for forwarding."""
        # Build a dedup key from message + timestamp (second-level granularity)
        dedup_str = event.get("message", "") + event.get("@timestamp", "")[:19]
        if self._dedup.is_duplicate(dedup_str):
            return

        # Stamp agent info
        event.setdefault("agent", {})
        event["agent"]["id"] = self.state.agent_id
        event["agent"]["hostname"] = self.state.hostname
        event["agent"]["version"] = AGENT_VERSION
        event["agent"]["type"] = "cybernest-agent"

        self._forwarder.enqueue(event)

    # ------------------------------------------------------------------
    # Command handler (called by forwarder on manager commands)
    # ------------------------------------------------------------------

    async def _handle_command(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a command received from the manager."""
        command = data.get("command", "")
        params = data.get("params", {})

        logger.info("command_received", command=command)

        handlers: Dict[str, Callable[..., Any]] = {
            "isolate": lambda: _isolate_host(),
            "unisolate": lambda: _unisolate_host(),
            "get_processes": lambda: _get_processes(),
            "get_connections": lambda: _get_connections(),
            "restart": lambda: self._restart(),
            "update": lambda: self._update(params),
            "get_status": lambda: self._get_status(),
        }

        handler = handlers.get(command)
        if handler is None:
            return {"error": f"Unknown command: {command}"}

        result = handler()
        if asyncio.iscoroutine(result):
            result = await result
        return result

    def _get_status(self) -> Dict[str, Any]:
        return {
            "agent_id": self.state.agent_id,
            "hostname": self.state.hostname,
            "os": f"{self.state.os_type} {self.state.os_version}",
            "version": AGENT_VERSION,
            "uptime": time.monotonic(),
            "collectors": [c.name for c in self._collectors],
            "forwarder": self._forwarder.stats,
            "health": self._get_health(),
        }

    async def _restart(self) -> Dict[str, Any]:
        """Restart the agent process."""
        logger.info("restart_requested")
        # Schedule restart after response is sent
        asyncio.get_event_loop().call_later(1.0, lambda: os.execv(sys.executable, [sys.executable] + sys.argv))
        return {"status": "restarting"}

    async def _update(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for agent self-update."""
        # In production this would download a new binary/package
        return {"status": "update_not_implemented", "current_version": AGENT_VERSION}

    def _get_health(self) -> Dict[str, Any]:
        """Return CPU / memory usage for heartbeat."""
        try:
            proc = psutil.Process()
            return {
                "cpu_percent": psutil.cpu_percent(interval=0),
                "memory_percent": psutil.virtual_memory().percent,
                "agent_cpu": proc.cpu_percent(interval=0),
                "agent_memory_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
                "disk_percent": psutil.disk_usage("/").percent if platform.system() != "Windows" else psutil.disk_usage("C:\\").percent,
            }
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Collector setup
    # ------------------------------------------------------------------

    def _setup_collectors(self) -> None:
        """Instantiate collectors based on OS and config."""
        os_type = self.state.os_type
        collectors_cfg = self.config.get("collectors", {})

        # OS-specific log collectors
        if os_type == "linux":
            syslog_cfg = collectors_cfg.get("linux_syslog", {})
            if syslog_cfg.get("enabled", True):
                cls = get_collector("linux_syslog")
                if cls:
                    self._collectors.append(
                        cls(
                            name="linux_syslog",
                            config=syslog_cfg,
                            agent_id=self.state.agent_id,
                            hostname=self.state.hostname,
                            emit_fn=self._emit_event,
                        )
                    )

        elif os_type == "windows":
            winevt_cfg = collectors_cfg.get("windows_event", {})
            if winevt_cfg.get("enabled", True):
                cls = get_collector("windows_event")
                if cls:
                    c = cls(
                        name="windows_event",
                        config=winevt_cfg,
                        agent_id=self.state.agent_id,
                        hostname=self.state.hostname,
                        emit_fn=self._emit_event,
                    )
                    # Set state_dir for checkpoints
                    c.config.setdefault(
                        "state_dir",
                        str(
                            Path(
                                self.config.get("agent", {}).get(
                                    "state_dir", str(DEFAULT_STATE_DIR)
                                )
                            )
                        ),
                    )
                    self._collectors.append(c)

            # Registry monitor (Windows only)
            reg_cfg = collectors_cfg.get("registry_monitor", {})
            if reg_cfg.get("enabled", True):
                cls = get_collector("registry_monitor")
                if cls:
                    self._collectors.append(
                        cls(
                            name="registry_monitor",
                            config=reg_cfg,
                            agent_id=self.state.agent_id,
                            hostname=self.state.hostname,
                            emit_fn=self._emit_event,
                        )
                    )

        elif os_type == "darwin":
            mac_cfg = collectors_cfg.get("macos_log", {})
            if mac_cfg.get("enabled", True):
                cls = get_collector("macos_log")
                if cls:
                    self._collectors.append(
                        cls(
                            name="macos_log",
                            config=mac_cfg,
                            agent_id=self.state.agent_id,
                            hostname=self.state.hostname,
                            emit_fn=self._emit_event,
                        )
                    )

        # Cross-platform collectors
        fim_cfg = collectors_cfg.get("fim", {})
        if fim_cfg.get("enabled", True):
            cls = get_collector("fim")
            if cls:
                self._collectors.append(
                    cls(
                        name="fim",
                        config=fim_cfg,
                        agent_id=self.state.agent_id,
                        hostname=self.state.hostname,
                        emit_fn=self._emit_event,
                    )
                )

        proc_cfg = collectors_cfg.get("process_monitor", {})
        if proc_cfg.get("enabled", True):
            cls = get_collector("process_monitor")
            if cls:
                self._collectors.append(
                    cls(
                        name="process_monitor",
                        config=proc_cfg,
                        agent_id=self.state.agent_id,
                        hostname=self.state.hostname,
                        emit_fn=self._emit_event,
                    )
                )

        net_cfg = collectors_cfg.get("network_monitor", {})
        if net_cfg.get("enabled", True):
            cls = get_collector("network_monitor")
            if cls:
                self._collectors.append(
                    cls(
                        name="network_monitor",
                        config=net_cfg,
                        agent_id=self.state.agent_id,
                        hostname=self.state.hostname,
                        emit_fn=self._emit_event,
                    )
                )

        logger.info(
            "collectors_configured",
            count=len(self._collectors),
            names=[c.name for c in self._collectors],
        )

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the agent."""
        self._running = True

        logger.info(
            "agent_starting",
            version=AGENT_VERSION,
            hostname=self.state.hostname,
            os=f"{self.state.os_type} {self.state.os_version}",
            manager=self._manager_ws_url,
        )

        # Auto-enroll
        await self._enroll()

        # Setup collectors
        self._setup_collectors()

        # Start forwarder
        forwarder_tasks = await self._forwarder.start()
        self._tasks.extend(forwarder_tasks)

        # Start collectors
        for collector in self._collectors:
            task = await collector.start()
            self._tasks.append(task)

        logger.info(
            "agent_running",
            agent_id=self.state.agent_id,
            tasks=len(self._tasks),
        )

        # Wait for all tasks (they run forever until cancelled)
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass

    async def shutdown(self) -> None:
        """Graceful shutdown."""
        logger.info("agent_shutting_down")
        self._running = False

        # Stop collectors
        for collector in self._collectors:
            try:
                await collector.stop()
            except Exception as exc:
                logger.warning("collector_stop_error", collector=collector.name, error=str(exc))

        # Stop forwarder (flushes queue to buffer)
        try:
            await self._forwarder.stop()
        except Exception as exc:
            logger.warning("forwarder_stop_error", error=str(exc))

        # Cancel remaining tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        logger.info("agent_stopped")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CyberNest SIEM Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config",
        "-c",
        default=str(DEFAULT_CONFIG),
        help=f"Path to config file (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"CyberNest Agent {AGENT_VERSION}",
    )
    return parser.parse_args()


async def _async_main(config_path: str) -> None:
    agent = CyberNestAgent(config_path)

    # Register signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler() -> None:
        if not shutdown_event.is_set():
            shutdown_event.set()

    # Register signals (Unix-style -- on Windows these may be limited)
    for sig_name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler for all signals
                signal.signal(sig, lambda s, f: _signal_handler())

    # Run agent in background, wait for shutdown signal
    agent_task = asyncio.create_task(agent.run())

    # Wait for either the agent to finish or a shutdown signal
    shutdown_task = asyncio.create_task(shutdown_event.wait())
    done, pending = await asyncio.wait(
        {agent_task, shutdown_task}, return_when=asyncio.FIRST_COMPLETED
    )

    if shutdown_event.is_set():
        await agent.shutdown()
    else:
        # Agent exited on its own
        for task in pending:
            task.cancel()


def main() -> None:
    args = _parse_args()
    config_path = args.config

    if not Path(config_path).exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(_async_main(config_path))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

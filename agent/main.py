"""
CyberNest Agent — Lightweight cross-platform log collector and security monitor.
Collects Windows Event Logs, Linux syslogs, FIM, process/network monitoring.
Forwards events to CyberNest Manager via REST API with local buffering.
"""

import asyncio
import json
import logging
import os
import platform
import queue
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cybernest-agent")

CONFIG_PATH = os.environ.get("CYBERNEST_AGENT_CONFIG", str(Path(__file__).parent / "config" / "agent.yml"))
STATE_FILE = Path(__file__).parent / "data" / "agent_state.json"


class AgentState:
    """Persistent agent state."""
    def __init__(self):
        self.agent_id: str = ""
        self.auth_key: str = ""
        self.hostname: str = platform.node()
        self.os_type: str = platform.system().lower()
        self.os_version: str = platform.version()
        self.agent_version: str = "1.0.0"
        self._load()

    def _load(self):
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text())
            self.agent_id = data.get("agent_id", "")
            self.auth_key = data.get("auth_key", "")

    def save(self):
        STATE_FILE.write_text(json.dumps({
            "agent_id": self.agent_id,
            "auth_key": self.auth_key,
        }))


class EventBuffer:
    """Thread-safe local event buffer with persistence fallback."""
    def __init__(self, max_size: int = 10000):
        self._queue: queue.Queue = queue.Queue(maxsize=max_size)
        self._overflow_file = STATE_FILE.parent / "buffer_overflow.jsonl"

    def put(self, event: dict):
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Persist to disk
            with open(self._overflow_file, "a") as f:
                f.write(json.dumps(event) + "\n")

    def get_batch(self, batch_size: int = 100) -> list[dict]:
        batch = []
        for _ in range(batch_size):
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    @property
    def size(self) -> int:
        return self._queue.qsize()


class CyberNestAgent:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        self.state = AgentState()
        self.buffer = EventBuffer(self.config.get("agent", {}).get("buffer_size", 10000))
        self.running = True

        manager = self.config.get("manager", {})
        proto = manager.get("protocol", "https")
        host = manager.get("host", "localhost")
        port = manager.get("port", 8000)
        self.base_url = f"{proto}://{host}:{port}{manager.get('api_path', '/api/v1')}"

        self._dedup_cache: set = set()
        self._collectors = []

    async def start(self):
        logger.info(f"CyberNest Agent v{self.state.agent_version} starting on {self.state.hostname}")
        logger.info(f"OS: {self.state.os_type} {self.state.os_version}")
        logger.info(f"Manager: {self.base_url}")

        # Register with manager
        if not self.state.agent_id:
            await self._register()
        else:
            logger.info(f"Agent ID: {self.state.agent_id}")

        # Start background tasks
        tasks = [
            asyncio.create_task(self._heartbeat_loop()),
            asyncio.create_task(self._forwarder_loop()),
        ]

        # Start collectors based on OS
        collectors_config = self.config.get("collectors", {})
        monitors_config = self.config.get("monitors", {})

        if self.state.os_type == "windows" and collectors_config.get("windows_event_log", {}).get("enabled"):
            tasks.append(asyncio.create_task(self._collect_windows_events()))

        if self.state.os_type == "linux" and collectors_config.get("linux_logs", {}).get("enabled"):
            tasks.append(asyncio.create_task(self._collect_linux_logs()))

        if monitors_config.get("file_integrity", {}).get("enabled"):
            tasks.append(asyncio.create_task(self._fim_monitor()))

        if monitors_config.get("process_monitor", {}).get("enabled"):
            tasks.append(asyncio.create_task(self._process_monitor()))

        if monitors_config.get("network_monitor", {}).get("enabled"):
            tasks.append(asyncio.create_task(self._network_monitor()))

        logger.info(f"Started {len(tasks)} background tasks")

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            self.running = False
            logger.info("Agent shutting down")

    async def _register(self):
        try:
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.post(f"{self.base_url}/agents/register", json={
                    "hostname": self.state.hostname,
                    "ip_address": self._get_primary_ip(),
                    "os_type": self.state.os_type,
                    "os_version": self.state.os_version,
                    "agent_version": self.state.agent_version,
                    "labels": self.config.get("agent", {}).get("labels", {}),
                    "group": self.config.get("agent", {}).get("group", "default"),
                })
                if resp.status_code == 201:
                    data = resp.json()
                    self.state.agent_id = data["id"]
                    self.state.save()
                    logger.info(f"Registered with Manager. Agent ID: {self.state.agent_id}")
                else:
                    logger.error(f"Registration failed: {resp.status_code} {resp.text}")
        except Exception as e:
            logger.error(f"Cannot reach Manager: {e}. Will retry...")
            self.state.agent_id = str(uuid.uuid4())
            self.state.save()

    async def _heartbeat_loop(self):
        interval = self.config.get("agent", {}).get("heartbeat_interval", 30)
        while self.running:
            try:
                import psutil
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory().percent
            except ImportError:
                cpu, mem = 0.0, 0.0

            try:
                async with httpx.AsyncClient(verify=False) as client:
                    await client.post(
                        f"{self.base_url}/agents/{self.state.agent_id}/heartbeat",
                        json={
                            "agent_id": self.state.agent_id,
                            "cpu_usage": cpu,
                            "memory_usage": mem,
                            "events_per_second": self.buffer.size / max(interval, 1),
                        },
                        timeout=10,
                    )
            except Exception as e:
                logger.debug(f"Heartbeat failed: {e}")

            await asyncio.sleep(interval)

    async def _forwarder_loop(self):
        """Forward buffered events to Manager in batches."""
        batch_size = self.config.get("agent", {}).get("batch_size", 100)
        while self.running:
            batch = self.buffer.get_batch(batch_size)
            if not batch:
                await asyncio.sleep(1)
                continue

            try:
                async with httpx.AsyncClient(verify=False) as client:
                    resp = await client.post(
                        f"{self.base_url}/events/ingest/batch",
                        json={"logs": batch},
                        timeout=30,
                    )
                    if resp.status_code != 200:
                        logger.warning(f"Batch ingest failed: {resp.status_code}")
                        # Re-queue events
                        for event in batch:
                            self.buffer.put(event)
            except Exception as e:
                logger.warning(f"Forwarder error: {e}. Re-queuing {len(batch)} events.")
                for event in batch:
                    self.buffer.put(event)
                await asyncio.sleep(5)

    def _emit_event(self, raw: str, source_type: str = "syslog", source: str = ""):
        """Add an event to the buffer with deduplication."""
        # Simple dedup: hash of raw log
        log_hash = hash(raw)
        if log_hash in self._dedup_cache:
            return
        self._dedup_cache.add(log_hash)
        if len(self._dedup_cache) > 50000:
            self._dedup_cache.clear()

        self.buffer.put({
            "raw": raw,
            "source": source or self.state.hostname,
            "source_type": source_type,
            "agent_id": self.state.agent_id,
            "tags": [f"agent:{self.state.hostname}"],
        })

    # ── Collectors ──

    async def _collect_windows_events(self):
        """Collect Windows Event Logs via win32evtlog."""
        try:
            import win32evtlog
            import win32evtlogutil
        except ImportError:
            logger.warning("pywin32 not installed — Windows Event Log collection disabled")
            return

        config = self.config["collectors"]["windows_event_log"]
        channels = config.get("channels", ["Security", "System", "Application"])
        poll_interval = config.get("poll_interval", 1)

        bookmarks: dict[str, int] = {}
        logger.info(f"Windows Event Log collector started: {channels}")

        while self.running:
            for channel in channels:
                try:
                    hand = win32evtlog.OpenEventLog(None, channel)
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    total = win32evtlog.GetNumberOfEventLogRecords(hand)

                    last_record = bookmarks.get(channel, total)
                    events = win32evtlog.ReadEventLog(hand, flags, 0)

                    for event in events:
                        if event.RecordNumber <= last_record:
                            continue
                        # Format as XML-like string
                        msg = win32evtlogutil.SafeFormatMessage(event, channel)
                        raw = (
                            f"<Event><System>"
                            f"<EventID>{event.EventID & 0xFFFF}</EventID>"
                            f"<Channel>{channel}</Channel>"
                            f"<Computer>{event.ComputerName}</Computer>"
                            f"<TimeCreated SystemTime='{event.TimeGenerated.isoformat()}'/>"
                            f"</System><EventData>{msg}</EventData></Event>"
                        )
                        self._emit_event(raw, source_type="windows", source=channel)
                        bookmarks[channel] = event.RecordNumber

                    win32evtlog.CloseEventLog(hand)
                except Exception as e:
                    logger.debug(f"Windows Event Log error ({channel}): {e}")

            await asyncio.sleep(poll_interval)

    async def _collect_linux_logs(self):
        """Tail Linux log files and emit new lines."""
        config = self.config["collectors"]["linux_logs"]
        paths = config.get("paths", [])
        poll_interval = config.get("poll_interval", 1)

        file_positions: dict[str, int] = {}
        logger.info(f"Linux log collector started: {len(paths)} files")

        while self.running:
            for log_path in paths:
                try:
                    p = Path(log_path)
                    if not p.exists():
                        continue

                    current_size = p.stat().st_size
                    last_pos = file_positions.get(log_path, current_size)  # Start at end

                    if current_size < last_pos:
                        last_pos = 0  # File rotated

                    if current_size > last_pos:
                        with open(log_path, "r", errors="replace") as f:
                            f.seek(last_pos)
                            for line in f:
                                line = line.strip()
                                if line:
                                    self._emit_event(line, source_type="linux", source=log_path)
                            file_positions[log_path] = f.tell()
                except Exception as e:
                    logger.debug(f"Log read error ({log_path}): {e}")

            await asyncio.sleep(poll_interval)

    async def _fim_monitor(self):
        """File Integrity Monitoring — detect file changes."""
        config = self.config["monitors"]["file_integrity"]
        paths = config.get("paths", [])
        interval = config.get("scan_interval", 300)

        file_hashes: dict[str, tuple[float, int]] = {}  # path -> (mtime, size)
        logger.info(f"FIM monitor started: {len(paths)} paths")

        while self.running:
            for base_path in paths:
                p = Path(base_path)
                if not p.exists():
                    continue
                try:
                    for file_path in (p.rglob("*") if p.is_dir() else [p]):
                        if not file_path.is_file():
                            continue
                        try:
                            stat = file_path.stat()
                            key = str(file_path)
                            current = (stat.st_mtime, stat.st_size)
                            prev = file_hashes.get(key)

                            if prev is None:
                                file_hashes[key] = current
                            elif prev != current:
                                file_hashes[key] = current
                                self._emit_event(
                                    json.dumps({
                                        "event_type": "fim",
                                        "action": "modified",
                                        "file_path": key,
                                        "old_mtime": prev[0],
                                        "new_mtime": current[0],
                                        "old_size": prev[1],
                                        "new_size": current[1],
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                    }),
                                    source_type="linux" if self.state.os_type != "windows" else "windows",
                                    source="fim",
                                )
                        except (PermissionError, OSError):
                            pass
                except Exception as e:
                    logger.debug(f"FIM scan error ({base_path}): {e}")

            await asyncio.sleep(interval)

    async def _process_monitor(self):
        """Monitor for new/suspicious processes."""
        config = self.config["monitors"]["process_monitor"]
        interval = config.get("scan_interval", 10)
        suspicious = set(n.lower() for n in config.get("suspicious_names", []))

        known_pids: set[int] = set()
        logger.info("Process monitor started")

        while self.running:
            try:
                import psutil
                current_pids = set()
                for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"]):
                    try:
                        info = proc.info
                        current_pids.add(info["pid"])

                        if info["pid"] not in known_pids and known_pids:
                            # New process detected
                            proc_name = (info["name"] or "").lower()
                            if proc_name in suspicious:
                                self._emit_event(
                                    json.dumps({
                                        "event_type": "process_alert",
                                        "action": "suspicious_process",
                                        "process_name": info["name"],
                                        "pid": info["pid"],
                                        "username": info.get("username", ""),
                                        "cmdline": " ".join(info.get("cmdline") or []),
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                    }),
                                    source_type=self.state.os_type,
                                    source="process_monitor",
                                )
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                known_pids = current_pids
            except ImportError:
                logger.warning("psutil not installed — process monitoring disabled")
                return

            await asyncio.sleep(interval)

    async def _network_monitor(self):
        """Monitor network connections for suspicious activity."""
        config = self.config["monitors"]["network_monitor"]
        interval = config.get("scan_interval", 15)
        suspicious_ports = set(config.get("alert_on_suspicious_ports", []))

        known_listeners: set[tuple] = set()
        logger.info("Network monitor started")

        while self.running:
            try:
                import psutil
                current_listeners = set()

                for conn in psutil.net_connections(kind="inet"):
                    if conn.status == "LISTEN":
                        listener = (conn.laddr.ip, conn.laddr.port)
                        current_listeners.add(listener)

                        if listener not in known_listeners and known_listeners:
                            self._emit_event(
                                json.dumps({
                                    "event_type": "network_alert",
                                    "action": "new_listener",
                                    "listen_ip": conn.laddr.ip,
                                    "listen_port": conn.laddr.port,
                                    "pid": conn.pid,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                }),
                                source_type=self.state.os_type,
                                source="network_monitor",
                            )

                    # Check outbound to suspicious ports
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        if conn.raddr.port in suspicious_ports:
                            self._emit_event(
                                json.dumps({
                                    "event_type": "network_alert",
                                    "action": "suspicious_outbound",
                                    "source_ip": conn.laddr.ip,
                                    "source_port": conn.laddr.port,
                                    "dest_ip": conn.raddr.ip,
                                    "dest_port": conn.raddr.port,
                                    "pid": conn.pid,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                }),
                                source_type=self.state.os_type,
                                source="network_monitor",
                            )

                known_listeners = current_listeners
            except ImportError:
                logger.warning("psutil not installed — network monitoring disabled")
                return

            await asyncio.sleep(interval)

    def _get_primary_ip(self) -> str:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


async def main():
    agent = CyberNestAgent(CONFIG_PATH)
    await agent.start()


if __name__ == "__main__":
    asyncio.run(main())

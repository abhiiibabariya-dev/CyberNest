"""
CyberNest Agent -- Network Monitor Collector

Polls psutil.net_connections() every N seconds.  Detects new connections
and new listening ports.  Records src_ip, src_port, dst_ip, dst_port,
protocol, state, pid, and process_name.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, Optional, Set, Tuple

import psutil

from . import BaseCollector, ecs_base_event, register_collector

# Protocol number -> name mapping (common ones)
_PROTO_MAP = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    58: "icmpv6",
}


def _resolve_process_name(pid: Optional[int]) -> str:
    """Best-effort process name resolution from PID."""
    if pid is None or pid == 0:
        return ""
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ""


# A listener is identified by (ip, port, family, type)
ListenerKey = Tuple[str, int, int, int]

# A connection is identified by (local_ip, local_port, remote_ip, remote_port, pid)
ConnKey = Tuple[str, int, str, int, Optional[int]]


@register_collector("network_monitor")
class NetworkMonitorCollector(BaseCollector):
    """Detect new network connections and listening ports."""

    async def _run(self) -> None:
        interval: float = self.config.get("interval", 5.0)
        alert_ports: Set[int] = set(self.config.get("alert_ports", [4444, 5555, 1337, 31337, 8443]))
        track_established: bool = self.config.get("track_established", True)
        track_listeners: bool = self.config.get("track_listeners", True)

        known_listeners: Set[ListenerKey] = set()
        known_connections: Set[ConnKey] = set()

        # Initial snapshot (don't alert on existing state)
        self._snapshot(known_listeners, known_connections)

        self.log.info(
            "network_monitor_started",
            interval=interval,
            initial_listeners=len(known_listeners),
            initial_connections=len(known_connections),
        )

        while self._running:
            await asyncio.sleep(interval)

            current_listeners: Set[ListenerKey] = set()
            current_connections: Set[ConnKey] = set()

            try:
                conns = psutil.net_connections(kind="inet")
            except (psutil.AccessDenied, OSError) as exc:
                self.log.debug("net_connections_error", error=str(exc))
                continue

            for conn in conns:
                laddr = conn.laddr
                raddr = conn.raddr
                status = conn.status

                local_ip = laddr.ip if laddr else ""
                local_port = laddr.port if laddr else 0
                remote_ip = raddr.ip if raddr else ""
                remote_port = raddr.port if raddr else 0
                pid = conn.pid

                # --- Listening ports ---
                if status == "LISTEN" and track_listeners:
                    key: ListenerKey = (local_ip, local_port, conn.family, conn.type)
                    current_listeners.add(key)

                    if key not in known_listeners:
                        proc_name = _resolve_process_name(pid)
                        ecs = self._build_listener_event(
                            local_ip, local_port, pid, proc_name, conn
                        )
                        self.emit(ecs)

                # --- Established connections ---
                elif status == "ESTABLISHED" and track_established:
                    ckey: ConnKey = (local_ip, local_port, remote_ip, remote_port, pid)
                    current_connections.add(ckey)

                    if ckey not in known_connections:
                        proc_name = _resolve_process_name(pid)
                        is_suspicious = remote_port in alert_ports
                        ecs = self._build_connection_event(
                            local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                            pid,
                            proc_name,
                            conn,
                            suspicious=is_suspicious,
                        )
                        self.emit(ecs)

            known_listeners = current_listeners
            known_connections = current_connections

    # ------------------------------------------------------------------

    def _snapshot(
        self,
        listeners: Set[ListenerKey],
        connections: Set[ConnKey],
    ) -> None:
        """Take an initial snapshot of the network state."""
        try:
            for conn in psutil.net_connections(kind="inet"):
                laddr = conn.laddr
                raddr = conn.raddr
                local_ip = laddr.ip if laddr else ""
                local_port = laddr.port if laddr else 0
                remote_ip = raddr.ip if raddr else ""
                remote_port = raddr.port if raddr else 0

                if conn.status == "LISTEN":
                    listeners.add((local_ip, local_port, conn.family, conn.type))
                elif conn.status == "ESTABLISHED":
                    connections.add(
                        (local_ip, local_port, remote_ip, remote_port, conn.pid)
                    )
        except (psutil.AccessDenied, OSError):
            pass

    def _build_listener_event(
        self,
        ip: str,
        port: int,
        pid: Optional[int],
        proc_name: str,
        conn: Any,
    ) -> Dict[str, Any]:
        ecs = ecs_base_event(
            event_kind="event",
            event_category="network",
            event_type="start",
            event_dataset="network_monitor",
            agent_id=self.agent_id,
            agent_hostname=self.hostname,
            message=f"New listener: {ip}:{port} (PID {pid}, {proc_name})",
        )
        ecs["event"]["action"] = "new_listener"
        ecs["server"] = {"ip": ip, "port": port}
        ecs["network"] = {
            "direction": "inbound",
            "type": "ipv4" if conn.family == 2 else "ipv6",
            "transport": "tcp" if conn.type == 1 else "udp",
        }
        ecs["process"] = {"pid": pid or 0, "name": proc_name}
        return ecs

    def _build_connection_event(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        pid: Optional[int],
        proc_name: str,
        conn: Any,
        *,
        suspicious: bool = False,
    ) -> Dict[str, Any]:
        ecs = ecs_base_event(
            event_kind="alert" if suspicious else "event",
            event_category="network",
            event_type="connection",
            event_dataset="network_monitor",
            agent_id=self.agent_id,
            agent_hostname=self.hostname,
            message=f"{'SUSPICIOUS ' if suspicious else ''}Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port} (PID {pid}, {proc_name})",
        )
        ecs["event"]["action"] = "connection_established"
        ecs["source"] = {"ip": src_ip, "port": src_port}
        ecs["destination"] = {"ip": dst_ip, "port": dst_port}
        ecs["network"] = {
            "direction": "outbound",
            "type": "ipv4" if conn.family == 2 else "ipv6",
            "transport": "tcp" if conn.type == 1 else "udp",
        }
        ecs["process"] = {"pid": pid or 0, "name": proc_name}
        if suspicious:
            ecs["cybernest"] = {"alerts": ["suspicious_port"]}
        return ecs

"""
CyberNest Agent -- TLS WebSocket Forwarder

aiohttp WebSocket client with mutual TLS:
  - SSL context loading agent cert + key + CA
  - Auth: send {"type": "auth", "api_key": "..."} first message
  - Event batching: up to 50 events or 1 second
  - Local queue: asyncio.Queue maxsize=10000
  - On disconnect: queue to local buffer file (JSONL)
  - Reconnect: exponential backoff 1s -> 2s -> 4s -> 8s -> max 60s
  - Heartbeat: {"type": "heartbeat"} every 30s
  - Receive and dispatch commands from manager
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import aiohttp
import structlog

logger = structlog.get_logger("cybernest.forwarder")


class TLSForwarder:
    """WebSocket-based event forwarder with TLS, batching, and offline buffering."""

    def __init__(
        self,
        *,
        manager_url: str,
        api_key: str,
        agent_id: str,
        # TLS
        ca_cert: str = "",
        client_cert: str = "",
        client_key: str = "",
        verify_ssl: bool = True,
        # Batching
        batch_size: int = 50,
        flush_interval: float = 1.0,
        # Queue
        queue_maxsize: int = 10000,
        # Buffer
        buffer_file: str = "event_buffer.jsonl",
        # Reconnect
        reconnect_base: float = 1.0,
        reconnect_max: float = 60.0,
        # Heartbeat
        heartbeat_interval: float = 30.0,
        # Command handler
        command_handler: Optional[Callable[[Dict[str, Any]], Any]] = None,
        # Health info callback
        health_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    ) -> None:
        self._manager_url = manager_url.rstrip("/")
        self._api_key = api_key
        self._agent_id = agent_id

        # TLS
        self._ca_cert = ca_cert
        self._client_cert = client_cert
        self._client_key = client_key
        self._verify_ssl = verify_ssl

        # Batching
        self._batch_size = batch_size
        self._flush_interval = flush_interval

        # Queue
        self._queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=queue_maxsize)

        # Buffer file (offline fallback)
        self._buffer_path = Path(buffer_file)
        self._buffer_path.parent.mkdir(parents=True, exist_ok=True)

        # Reconnect
        self._reconnect_base = reconnect_base
        self._reconnect_max = reconnect_max

        # Heartbeat
        self._heartbeat_interval = heartbeat_interval

        # Callbacks
        self._command_handler = command_handler
        self._health_fn = health_fn

        # State
        self._running = False
        self._connected = False
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._events_sent: int = 0
        self._events_buffered: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self) -> List[asyncio.Task]:
        """Start forwarder tasks. Returns list of tasks for the caller to await."""
        self._running = True
        tasks = [
            asyncio.create_task(self._connection_loop(), name="forwarder-conn"),
            asyncio.create_task(self._sender_loop(), name="forwarder-send"),
            asyncio.create_task(self._drain_buffer_loop(), name="forwarder-drain"),
        ]
        return tasks

    async def stop(self) -> None:
        """Graceful shutdown: flush remaining queue to buffer file."""
        self._running = False
        await self._flush_queue_to_buffer()
        if self._ws and not self._ws.closed:
            await self._ws.close()
        if self._session and not self._session.closed:
            await self._session.close()
        logger.info("forwarder_stopped", events_sent=self._events_sent)

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """Enqueue an event for forwarding. Returns False if queue is full."""
        try:
            self._queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            self._buffer_to_file([event])
            self._events_buffered += 1
            return False

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "connected": self._connected,
            "queue_size": self._queue.qsize(),
            "events_sent": self._events_sent,
            "events_buffered": self._events_buffered,
        }

    # ------------------------------------------------------------------
    # SSL context
    # ------------------------------------------------------------------

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self._verify_ssl and not self._client_cert:
            return False  # type: ignore[return-value]  # aiohttp accepts False

        ctx = ssl.create_default_context()

        if self._ca_cert and os.path.isfile(self._ca_cert):
            ctx.load_verify_locations(self._ca_cert)

        if self._client_cert and os.path.isfile(self._client_cert):
            ctx.load_cert_chain(
                certfile=self._client_cert,
                keyfile=self._client_key if self._client_key and os.path.isfile(self._client_key) else None,
            )

        if not self._verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        return ctx

    # ------------------------------------------------------------------
    # Connection loop with exponential backoff
    # ------------------------------------------------------------------

    async def _connection_loop(self) -> None:
        backoff = self._reconnect_base

        while self._running:
            try:
                ssl_ctx = self._build_ssl_context()
                ws_url = f"{self._manager_url}/ws/agent"

                self._session = aiohttp.ClientSession()
                self._ws = await self._session.ws_connect(
                    ws_url,
                    ssl=ssl_ctx,
                    heartbeat=self._heartbeat_interval,
                    timeout=aiohttp.ClientWSTimeout(ws_close=10.0),
                )

                # Authenticate
                await self._ws.send_json({
                    "type": "auth",
                    "api_key": self._api_key,
                    "agent_id": self._agent_id,
                })

                # Wait for auth response
                auth_resp = await asyncio.wait_for(self._ws.receive_json(), timeout=10.0)
                if auth_resp.get("type") != "auth_ok":
                    logger.error("auth_failed", response=auth_resp)
                    await self._ws.close()
                    await self._session.close()
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, self._reconnect_max)
                    continue

                logger.info("forwarder_connected", url=ws_url)
                self._connected = True
                backoff = self._reconnect_base

                # Start heartbeat and receiver concurrently
                hb_task = asyncio.create_task(self._heartbeat_loop())
                recv_task = asyncio.create_task(self._receive_loop())

                done, pending = await asyncio.wait(
                    {hb_task, recv_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass

            except (
                aiohttp.ClientError,
                aiohttp.WSServerHandshakeError,
                ConnectionRefusedError,
                OSError,
                asyncio.TimeoutError,
            ) as exc:
                logger.warning("connection_failed", error=str(exc), backoff=backoff)
            except asyncio.CancelledError:
                break
            finally:
                self._connected = False
                if self._ws and not self._ws.closed:
                    try:
                        await self._ws.close()
                    except Exception:
                        pass
                if self._session and not self._session.closed:
                    try:
                        await self._session.close()
                    except Exception:
                        pass

            if self._running:
                logger.info("reconnecting", backoff=backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, self._reconnect_max)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        while self._running and self._connected:
            try:
                payload: Dict[str, Any] = {
                    "type": "heartbeat",
                    "agent_id": self._agent_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "queue_size": self._queue.qsize(),
                    "events_sent": self._events_sent,
                }
                if self._health_fn:
                    payload["health"] = self._health_fn()

                if self._ws and not self._ws.closed:
                    await self._ws.send_json(payload)
            except Exception as exc:
                logger.debug("heartbeat_send_error", error=str(exc))
                return
            await asyncio.sleep(self._heartbeat_interval)

    # ------------------------------------------------------------------
    # Receive commands from manager
    # ------------------------------------------------------------------

    async def _receive_loop(self) -> None:
        if not self._ws:
            return

        async for msg in self._ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue

                msg_type = data.get("type", "")

                if msg_type == "command" and self._command_handler:
                    try:
                        result = self._command_handler(data)
                        if asyncio.iscoroutine(result):
                            result = await result
                        # Send response
                        if self._ws and not self._ws.closed:
                            await self._ws.send_json({
                                "type": "command_response",
                                "command_id": data.get("command_id", ""),
                                "agent_id": self._agent_id,
                                "result": result,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })
                    except Exception as exc:
                        logger.error("command_handler_error", error=str(exc))
                        if self._ws and not self._ws.closed:
                            await self._ws.send_json({
                                "type": "command_response",
                                "command_id": data.get("command_id", ""),
                                "agent_id": self._agent_id,
                                "error": str(exc),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })

                elif msg_type == "ping":
                    if self._ws and not self._ws.closed:
                        await self._ws.send_json({"type": "pong", "agent_id": self._agent_id})

            elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                logger.warning("ws_closed_or_error", type=str(msg.type))
                break

    # ------------------------------------------------------------------
    # Sender: batches events from queue and sends over WS
    # ------------------------------------------------------------------

    async def _sender_loop(self) -> None:
        while self._running:
            if not self._connected or not self._ws or self._ws.closed:
                await asyncio.sleep(0.5)
                continue

            batch = await self._collect_batch()
            if not batch:
                continue

            try:
                payload = {
                    "type": "events",
                    "agent_id": self._agent_id,
                    "count": len(batch),
                    "events": batch,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                await self._ws.send_json(payload)
                self._events_sent += len(batch)
            except Exception as exc:
                logger.warning(
                    "send_batch_failed",
                    error=str(exc),
                    batch_size=len(batch),
                )
                # Re-queue or buffer
                self._buffer_to_file(batch)
                self._events_buffered += len(batch)
                self._connected = False

    async def _collect_batch(self) -> List[Dict[str, Any]]:
        """Collect up to batch_size events or wait up to flush_interval."""
        batch: List[Dict[str, Any]] = []
        deadline = asyncio.get_event_loop().time() + self._flush_interval

        while len(batch) < self._batch_size:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                evt = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                batch.append(evt)
            except asyncio.TimeoutError:
                break
        return batch

    # ------------------------------------------------------------------
    # Buffer file management
    # ------------------------------------------------------------------

    def _buffer_to_file(self, events: List[Dict[str, Any]]) -> None:
        """Append events to the local buffer file."""
        try:
            with open(self._buffer_path, "a", encoding="utf-8") as fh:
                for evt in events:
                    fh.write(json.dumps(evt, default=str) + "\n")
        except OSError as exc:
            logger.error("buffer_write_failed", error=str(exc))

    async def _drain_buffer_loop(self) -> None:
        """Periodically drain the buffer file when connected."""
        while self._running:
            await asyncio.sleep(10.0)

            if not self._connected or not self._ws or self._ws.closed:
                continue

            if not self._buffer_path.exists():
                continue

            try:
                stat = self._buffer_path.stat()
                if stat.st_size == 0:
                    continue
            except OSError:
                continue

            # Read and re-enqueue
            events: List[Dict[str, Any]] = []
            try:
                with open(self._buffer_path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                events.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            except OSError:
                continue

            if not events:
                continue

            # Clear the buffer file
            try:
                self._buffer_path.write_text("")
            except OSError:
                pass

            # Re-enqueue (they'll go through the normal send path)
            enqueued = 0
            for evt in events:
                try:
                    self._queue.put_nowait(evt)
                    enqueued += 1
                except asyncio.QueueFull:
                    # Put remaining back in buffer
                    remaining = events[events.index(evt):]
                    self._buffer_to_file(remaining)
                    break

            if enqueued:
                logger.info("buffer_drained", count=enqueued)

    async def _flush_queue_to_buffer(self) -> None:
        """On shutdown, flush anything remaining in the queue to the buffer file."""
        events: List[Dict[str, Any]] = []
        while not self._queue.empty():
            try:
                events.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if events:
            self._buffer_to_file(events)
            logger.info("queue_flushed_to_buffer", count=len(events))

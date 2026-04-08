"""
CyberNest Manager -- Agent WebSocket Receiver.

Async WebSocket server on the configured agent port (5601) that authenticates
agents via api_key, routes incoming events to Kafka, handles heartbeats,
and delivers commands from Redis pub/sub to connected agents.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

import websockets
from sqlalchemy import select, update

from manager.config import get_settings
from manager.db.database import AsyncSessionLocal
from manager.db.models import Agent, AgentStatusEnum
from shared.utils.crypto import hash_api_key
from shared.utils.kafka_utils import KafkaProducerManager, Topics
from shared.utils.logger import get_logger

logger = get_logger("manager.agent_receiver")
settings = get_settings()

# Track connected agents: agent_id -> websocket
_connected_agents: dict[str, websockets.WebSocketServerProtocol] = {}


async def authenticate_agent(
    api_key: str,
) -> Optional[dict]:
    """Verify an agent's API key and return agent info if valid."""
    key_hash = hash_api_key(api_key)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Agent).where(Agent.api_key_hash == key_hash)
        )
        agent = result.scalar_one_or_none()
        if agent is None:
            return None

        # Update status to online
        agent.status = AgentStatusEnum.online
        agent.last_seen = datetime.now(timezone.utc)
        db.add(agent)
        await db.commit()

        return {
            "id": str(agent.id),
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
        }


async def handle_agent_disconnect(agent_id: str) -> None:
    """Mark agent as offline when the WebSocket connection drops."""
    _connected_agents.pop(agent_id, None)

    async with AsyncSessionLocal() as db:
        await db.execute(
            update(Agent)
            .where(Agent.agent_id == agent_id)
            .values(status=AgentStatusEnum.offline, last_seen=datetime.now(timezone.utc))
        )
        await db.commit()

    logger.info("agent disconnected", agent_id=agent_id)


async def subscribe_agent_commands(
    agent_id: str,
    websocket: websockets.WebSocketServerProtocol,
    redis_client,
) -> None:
    """Subscribe to Redis pub/sub for agent commands and forward them via WebSocket."""
    if redis_client is None:
        return

    pubsub = redis_client.pubsub()
    channel = f"agent:command:{agent_id}"
    await pubsub.subscribe(channel)

    try:
        while True:
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=1.0
            )
            if message and message.get("type") == "message":
                data = message["data"]
                if isinstance(data, bytes):
                    data = data.decode("utf-8")
                try:
                    await websocket.send(json.dumps({
                        "type": "command",
                        "payload": json.loads(data),
                    }))
                except Exception:
                    break
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.warning("command subscription error", agent_id=agent_id, error=str(exc))
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()


async def handle_agent_connection(
    websocket: websockets.WebSocketServerProtocol,
    path: str,
) -> None:
    """Handle a single agent WebSocket connection."""
    producer = KafkaProducerManager(settings.KAFKA_BOOTSTRAP)
    agent_info = None
    command_task = None

    try:
        # First message must be authentication
        try:
            auth_msg = await asyncio.wait_for(websocket.recv(), timeout=10)
            auth_data = json.loads(auth_msg)
        except (asyncio.TimeoutError, json.JSONDecodeError):
            await websocket.close(4001, "Authentication timeout or invalid data")
            return

        api_key = auth_data.get("api_key", "")
        agent_info = await authenticate_agent(api_key)
        if agent_info is None:
            await websocket.close(4003, "Invalid API key")
            return

        agent_id = agent_info["agent_id"]
        _connected_agents[agent_id] = websocket

        logger.info(
            "agent connected",
            agent_id=agent_id,
            hostname=agent_info["hostname"],
        )

        # Send auth success
        await websocket.send(json.dumps({
            "type": "auth_success",
            "agent_id": agent_id,
        }))

        # Start command subscription in background
        try:
            import redis.asyncio as aioredis
            redis_client = aioredis.from_url(settings.REDIS_URL)
            command_task = asyncio.create_task(
                subscribe_agent_commands(agent_id, websocket, redis_client)
            )
        except Exception:
            redis_client = None
            command_task = None

        # Ensure Kafka producer is started
        if not producer.is_started:
            try:
                await producer.start()
            except Exception as exc:
                logger.error("kafka producer start failed", error=str(exc))

        # Main message loop
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type", "event")

                if msg_type == "heartbeat":
                    await _handle_heartbeat(agent_id, data)
                    await websocket.send(json.dumps({"type": "heartbeat_ack"}))

                elif msg_type == "event":
                    event_data = data.get("payload", data)
                    event_data["cybernest"] = event_data.get("cybernest", {})
                    event_data["cybernest"]["agent_id"] = agent_id
                    event_data["cybernest"]["ingested_at"] = datetime.now(timezone.utc).isoformat()

                    # Determine topic based on event source
                    topic = _determine_topic(event_data)

                    if producer.is_started:
                        await producer.send_event(
                            topic=topic,
                            key=agent_id,
                            value=event_data,
                        )

                elif msg_type == "events_batch":
                    events = data.get("events", [])
                    for event_data in events:
                        event_data["cybernest"] = event_data.get("cybernest", {})
                        event_data["cybernest"]["agent_id"] = agent_id
                        event_data["cybernest"]["ingested_at"] = datetime.now(timezone.utc).isoformat()

                        topic = _determine_topic(event_data)
                        if producer.is_started:
                            await producer.send_event(
                                topic=topic,
                                key=agent_id,
                                value=event_data,
                            )

                    await websocket.send(json.dumps({
                        "type": "batch_ack",
                        "count": len(events),
                    }))

                elif msg_type == "command_response":
                    # Forward command response to Redis
                    if redis_client:
                        await redis_client.publish(
                            f"agent:response:{agent_id}",
                            json.dumps(data),
                        )

            except json.JSONDecodeError:
                logger.warning("invalid JSON from agent", agent_id=agent_id)
            except Exception as exc:
                logger.error(
                    "error processing agent message",
                    agent_id=agent_id,
                    error=str(exc),
                )

    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as exc:
        logger.error("agent connection error", error=str(exc))
    finally:
        if command_task:
            command_task.cancel()
            try:
                await command_task
            except asyncio.CancelledError:
                pass

        if agent_info:
            await handle_agent_disconnect(agent_info["agent_id"])


async def _handle_heartbeat(agent_id: str, data: dict) -> None:
    """Process a heartbeat message and update agent status in DB."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Agent).where(Agent.agent_id == agent_id)
        )
        agent = result.scalar_one_or_none()
        if agent:
            agent.last_seen = datetime.now(timezone.utc)
            agent.status = AgentStatusEnum.online

            # Update telemetry if provided
            config = dict(agent.config_json) if agent.config_json else {}
            if "cpu_usage" in data:
                config["cpu_usage"] = data["cpu_usage"]
            if "memory_usage" in data:
                config["memory_usage"] = data["memory_usage"]
            if "eps" in data:
                config["eps"] = data["eps"]
            if "uptime_seconds" in data:
                config["uptime_seconds"] = data["uptime_seconds"]
            agent.config_json = config

            db.add(agent)
            await db.commit()


def _determine_topic(event_data: dict) -> str:
    """Determine the Kafka topic based on the event source/type."""
    source_name = (
        event_data.get("cybernest", {}).get("source_name", "")
        or event_data.get("event", {}).get("module", "")
        or ""
    ).lower()

    if "windows" in source_name or "eventlog" in source_name:
        return Topics.RAW_WINDOWS
    elif "linux" in source_name or "auditd" in source_name or "syslog" in source_name:
        return Topics.RAW_LINUX
    elif "network" in source_name or "firewall" in source_name or "ids" in source_name:
        return Topics.RAW_NETWORK
    elif "cloud" in source_name or "aws" in source_name or "azure" in source_name:
        return Topics.RAW_CLOUD
    elif "application" in source_name or "webapp" in source_name:
        return Topics.RAW_APPLICATION
    else:
        return Topics.RAW_SYSLOG


async def start_agent_receiver(redis_client=None) -> None:
    """Start the agent WebSocket receiver server."""
    port = settings.AGENT_TLS_PORT

    server = await websockets.serve(
        handle_agent_connection,
        "0.0.0.0",
        port,
        ping_interval=30,
        ping_timeout=10,
        max_size=10 * 1024 * 1024,  # 10 MB max message
        close_timeout=5,
    )

    logger.info("agent receiver started", port=port)

    try:
        await asyncio.Future()  # Run forever
    except asyncio.CancelledError:
        server.close()
        await server.wait_closed()
        logger.info("agent receiver stopped")


def get_connected_agents() -> dict[str, str]:
    """Return a mapping of connected agent_ids to their status."""
    return {
        agent_id: "connected"
        for agent_id in _connected_agents
    }

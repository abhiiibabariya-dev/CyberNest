"""
CyberNest SOAR Action -- Isolate Endpoint.

Sends an endpoint isolation command to a CyberNest agent via Redis pub/sub.
The agent receives the command on its dedicated channel and applies network
isolation rules locally (Windows Firewall / iptables).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

import redis.asyncio as aioredis

from soar.actions import BaseAction, register_action


REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@register_action
class IsolateEndpoint(BaseAction):
    """Isolate an endpoint by sending a command to its CyberNest agent."""

    name = "isolate_endpoint"
    description = (
        "Send an 'isolate' command to a CyberNest agent via Redis pub/sub. "
        "The agent will apply network isolation rules on the host."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        agent_id: str = params.get("agent_id", "")
        hostname: str = params.get("hostname", "")
        reason: str = params.get("reason", "Isolated by CyberNest SOAR playbook")
        allow_cybernest: bool = params.get("allow_cybernest_traffic", True)
        redis_url: str = params.get("redis_url") or context.get("config", {}).get("redis_url") or REDIS_URL

        if not agent_id and not hostname:
            return self.result(
                False,
                error="Either 'agent_id' or 'hostname' is required",
            )

        # Resolve agent_id from hostname if needed
        effective_agent_id = agent_id or hostname

        command_id = uuid.uuid4().hex
        channel = f"cybernest:agent:{effective_agent_id}:commands"

        command_payload = {
            "command_id": command_id,
            "command": "isolate",
            "params": {
                "action": "enable",
                "allow_cybernest_traffic": allow_cybernest,
                "reason": reason,
            },
            "issued_by": "soar_engine",
            "issued_at": time.time(),
            "alert_id": context.get("alert", {}).get("alert_id", ""),
            "playbook": context.get("playbook_name", ""),
        }

        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
            try:
                # Publish the command
                receivers = await client.publish(channel, json.dumps(command_payload))

                # Also store the command in a list for agents that reconnect
                command_queue_key = f"cybernest:agent:{effective_agent_id}:command_queue"
                await client.lpush(command_queue_key, json.dumps(command_payload))
                await client.expire(command_queue_key, 86400)  # 24-hour TTL

                # Record command status for tracking
                status_key = f"cybernest:commands:{command_id}"
                await client.hset(status_key, mapping={
                    "command_id": command_id,
                    "agent_id": effective_agent_id,
                    "command": "isolate",
                    "status": "sent" if receivers > 0 else "queued",
                    "receivers": str(receivers),
                    "issued_at": str(time.time()),
                })
                await client.expire(status_key, 86400)

            finally:
                await client.aclose()

        except Exception as exc:
            return self.result(False, error=f"Redis publish failed: {exc}")

        return self.result(
            True,
            output={
                "command_id": command_id,
                "agent_id": effective_agent_id,
                "channel": channel,
                "receivers": receivers,
                "status": "sent" if receivers > 0 else "queued",
                "message": (
                    f"Isolate command sent to {receivers} subscriber(s)"
                    if receivers > 0
                    else "Isolate command queued (agent not currently connected)"
                ),
            },
        )

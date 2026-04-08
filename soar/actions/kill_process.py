"""
CyberNest SOAR Action -- Kill Process.

Sends a kill_process command to a CyberNest agent via Redis pub/sub.
The agent terminates the specified process by PID or process name.
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
class KillProcess(BaseAction):
    """Kill a process on a remote endpoint via the CyberNest agent."""

    name = "kill_process"
    description = (
        "Send a kill_process command to a CyberNest agent via Redis pub/sub "
        "to terminate a process by PID or process name."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        agent_id: str = params.get("agent_id", "")
        hostname: str = params.get("hostname", "")
        pid: int | str | None = params.get("pid")
        process_name: str = params.get("process_name", "")
        reason: str = params.get("reason", "Process killed by CyberNest SOAR")
        force: bool = params.get("force", True)
        redis_url: str = params.get("redis_url") or context.get("config", {}).get("redis_url") or REDIS_URL

        if not agent_id and not hostname:
            return self.result(
                False,
                error="Either 'agent_id' or 'hostname' is required",
            )
        if not pid and not process_name:
            return self.result(
                False,
                error="Either 'pid' or 'process_name' is required",
            )

        effective_agent_id = agent_id or hostname
        command_id = uuid.uuid4().hex
        channel = f"cybernest:agent:{effective_agent_id}:commands"

        kill_params: dict[str, Any] = {
            "reason": reason,
            "force": force,
        }
        if pid is not None:
            kill_params["pid"] = int(pid)
        if process_name:
            kill_params["process_name"] = process_name

        command_payload = {
            "command_id": command_id,
            "command": "kill_process",
            "params": kill_params,
            "issued_by": "soar_engine",
            "issued_at": time.time(),
            "alert_id": context.get("alert", {}).get("alert_id", ""),
            "playbook": context.get("playbook_name", ""),
        }

        try:
            client = aioredis.from_url(redis_url, decode_responses=True)
            try:
                receivers = await client.publish(channel, json.dumps(command_payload))

                # Queue for agents that are temporarily disconnected
                queue_key = f"cybernest:agent:{effective_agent_id}:command_queue"
                await client.lpush(queue_key, json.dumps(command_payload))
                await client.expire(queue_key, 86400)

                # Track command status
                status_key = f"cybernest:commands:{command_id}"
                await client.hset(status_key, mapping={
                    "command_id": command_id,
                    "agent_id": effective_agent_id,
                    "command": "kill_process",
                    "target_pid": str(pid or ""),
                    "target_name": process_name,
                    "status": "sent" if receivers > 0 else "queued",
                    "receivers": str(receivers),
                    "issued_at": str(time.time()),
                })
                await client.expire(status_key, 86400)

            finally:
                await client.aclose()

        except Exception as exc:
            return self.result(False, error=f"Redis publish failed: {exc}")

        target_desc = f"PID {pid}" if pid else f"process '{process_name}'"
        return self.result(
            True,
            output={
                "command_id": command_id,
                "agent_id": effective_agent_id,
                "channel": channel,
                "target_pid": pid,
                "target_process_name": process_name,
                "receivers": receivers,
                "status": "sent" if receivers > 0 else "queued",
                "message": (
                    f"Kill command for {target_desc} sent to {receivers} subscriber(s)"
                    if receivers > 0
                    else f"Kill command for {target_desc} queued (agent offline)"
                ),
            },
        )

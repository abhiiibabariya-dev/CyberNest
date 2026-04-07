"""CyberNest — Agent data model for registration and health tracking."""

from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field


class AgentRegistration(BaseModel):
    """Data sent by agent during enrollment with the Manager."""
    hostname: str
    ip_address: str
    os_type: str
    os_version: str | None = None
    agent_version: str
    labels: dict[str, str] = Field(default_factory=dict)
    agent_group: str = "default"


class AgentHeartbeat(BaseModel):
    """Periodic health check sent by agent every 30s."""
    agent_id: str
    hostname: str
    cpu_usage: float | None = None
    memory_usage: float | None = None
    eps: float | None = None
    collectors_status: dict[str, str] = Field(default_factory=dict)
    uptime_seconds: int | None = None


class AgentInfo(BaseModel):
    """Full agent record returned by the API."""
    id: str
    agent_id: str
    hostname: str
    ip_address: str
    os_type: str
    os_version: str | None
    agent_version: str
    status: str
    agent_group: str | None
    labels: dict | None
    cpu_usage: float | None
    memory_usage: float | None
    eps: float | None
    last_seen: str | None
    enrolled_at: str

    model_config = {"from_attributes": True}


class AgentCommand(BaseModel):
    """Remote command to send to an agent."""
    command: str  # isolate, restart, update, collect_forensics
    parameters: dict = Field(default_factory=dict)
    timeout: int = 60

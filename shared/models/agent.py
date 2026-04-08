"""
CyberNest Agent Model.

Pydantic v2 models for agent registration, heartbeats, and full agent records
used by the manager service for fleet management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class AgentStatus(str, Enum):
    """Agent lifecycle states."""

    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    ENROLLING = "enrolling"
    UNENROLLED = "unenrolled"
    UPDATING = "updating"
    ISOLATED = "isolated"
    ERROR = "error"


class AgentModel(BaseModel):
    """Full agent record stored in the database and returned by the API.

    Represents a single endpoint agent enrolled with the CyberNest manager.
    """

    model_config = {
        "populate_by_name": True,
        "from_attributes": True,
        "extra": "allow",
    }

    # --- Identity ----------------------------------------------------------
    agent_id: str = Field(
        default_factory=lambda: uuid4().hex,
        description="Unique agent identifier.",
    )
    hostname: str = Field(
        ..., description="Hostname of the enrolled endpoint."
    )
    ip: str = Field(
        ..., description="Primary IP address of the agent."
    )

    # --- System info -------------------------------------------------------
    os: str = Field(
        ..., description="Operating system name (e.g. Windows, Linux, macOS)."
    )
    os_version: Optional[str] = Field(
        None, description="OS version string."
    )
    architecture: Optional[str] = Field(
        None,
        description="CPU architecture (e.g. x86_64, arm64).",
    )
    version: str = Field(
        default="0.0.0",
        description="Agent software version.",
    )

    # --- Status ------------------------------------------------------------
    status: AgentStatus = Field(
        default=AgentStatus.ENROLLING,
        description="Current agent status.",
    )

    # --- Authentication ----------------------------------------------------
    api_key: Optional[str] = Field(
        None,
        description="Hashed API key for agent authentication (never stored in plaintext).",
    )

    # --- Timestamps --------------------------------------------------------
    enrolled_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the agent was first enrolled.",
    )
    last_seen: Optional[datetime] = Field(
        None,
        description="Last heartbeat timestamp.",
    )

    # --- Configuration -----------------------------------------------------
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Agent configuration (log sources, collection intervals, etc.).",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="User-defined tags for grouping/filtering agents.",
    )
    collectors: list[str] = Field(
        default_factory=list,
        description="Active collector module names (e.g. syslog, eventlog, auditd).",
    )

    # --- Telemetry ---------------------------------------------------------
    cpu_usage: Optional[float] = Field(
        None, ge=0.0, le=100.0, description="Last reported CPU usage %."
    )
    memory_usage: Optional[float] = Field(
        None, ge=0.0, le=100.0, description="Last reported memory usage %."
    )
    eps: Optional[float] = Field(
        None, ge=0.0, description="Events per second throughput."
    )
    uptime_seconds: Optional[int] = Field(
        None, ge=0, description="Agent process uptime in seconds."
    )
    agent_group: str = Field(
        default="default",
        description="Agent group for policy assignment.",
    )
    labels: dict[str, str] = Field(
        default_factory=dict,
        description="Key-value labels for metadata.",
    )

    # --- Validators --------------------------------------------------------
    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, v: Any) -> Any:
        """Accept string status values case-insensitively."""
        if isinstance(v, str):
            return v.lower()
        return v

    @field_validator("enrolled_at", "last_seen", mode="before")
    @classmethod
    def parse_datetime_strings(cls, v: Any) -> Any:
        """Accept ISO format strings for datetime fields."""
        if isinstance(v, str) and v:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def deduplicate_tags(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return list(dict.fromkeys(v))

    @field_validator("collectors", mode="before")
    @classmethod
    def deduplicate_collectors(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return list(dict.fromkeys(v))


# ---------------------------------------------------------------------------
# Sub-models for API request/response
# ---------------------------------------------------------------------------

class AgentRegistration(BaseModel):
    """Data sent by an agent during enrollment with the manager."""

    model_config = {"populate_by_name": True, "extra": "allow"}

    hostname: str
    ip: str = Field(..., alias="ip_address")
    os: str = Field(..., alias="os_type")
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    version: str = Field(..., alias="agent_version")
    labels: dict[str, str] = Field(default_factory=dict)
    agent_group: str = "default"
    collectors: list[str] = Field(default_factory=list)


class AgentHeartbeat(BaseModel):
    """Periodic health check sent by the agent every 30s."""

    model_config = {"populate_by_name": True, "extra": "allow"}

    agent_id: str
    hostname: str
    cpu_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    memory_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    eps: Optional[float] = Field(None, ge=0.0)
    collectors_status: dict[str, str] = Field(default_factory=dict)
    uptime_seconds: Optional[int] = Field(None, ge=0)


class AgentCommand(BaseModel):
    """Remote command to dispatch to an agent."""

    model_config = {"populate_by_name": True, "extra": "allow"}

    command: str  # isolate, restart, update, collect_forensics, run_scan
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout: int = Field(default=60, ge=1, le=3600)


# Backward-compatible aliases
AgentInfo = AgentModel

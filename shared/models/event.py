"""CyberNest — ECS (Elastic Common Schema) Event Model.

Full Pydantic model for normalized security events flowing through the pipeline.
All fields follow ECS 8.x naming conventions for Elasticsearch compatibility.
"""

from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class ECSSource(BaseModel):
    """Source endpoint — where the event originated from (attacker side)."""
    ip: str | None = None
    port: int | None = None
    domain: str | None = None
    mac: str | None = None
    geo: dict[str, Any] | None = None
    as_: dict[str, Any] | None = Field(None, alias="as")


class ECSDestination(BaseModel):
    """Destination endpoint — the target of the action (defender side)."""
    ip: str | None = None
    port: int | None = None
    domain: str | None = None
    mac: str | None = None
    geo: dict[str, Any] | None = None


class ECSUser(BaseModel):
    """User context — who performed the action."""
    name: str | None = None
    domain: str | None = None
    id: str | None = None
    email: str | None = None
    target: dict[str, Any] | None = None


class ECSProcess(BaseModel):
    """Process context — which process was involved."""
    name: str | None = None
    pid: int | None = None
    command_line: str | None = None
    executable: str | None = None
    hash: dict[str, str] | None = None
    parent: dict[str, Any] | None = None
    working_directory: str | None = None
    args: list[str] | None = None


class ECSHost(BaseModel):
    """Host context — which machine the event occurred on."""
    hostname: str | None = None
    ip: str | None = None
    mac: str | None = None
    os: dict[str, Any] | None = None
    architecture: str | None = None


class ECSNetwork(BaseModel):
    """Network context — transport layer details."""
    protocol: str | None = None
    transport: str | None = None
    direction: str | None = None
    bytes: int | None = None
    packets: int | None = None
    community_id: str | None = None


class ECSFile(BaseModel):
    """File context — for FIM and file-based events."""
    path: str | None = None
    name: str | None = None
    extension: str | None = None
    size: int | None = None
    hash: dict[str, str] | None = None
    owner: str | None = None
    group: str | None = None
    mode: str | None = None
    target_path: str | None = None


class ECSRule(BaseModel):
    """Rule/detection context — what matched."""
    id: str | None = None
    name: str | None = None
    level: int | None = None
    category: str | None = None
    description: str | None = None
    mitre: dict[str, Any] | None = None


class ECSEvent(BaseModel):
    """Event metadata — classification of this event."""
    module: str | None = None
    category: str | None = None
    action: str | None = None
    outcome: str | None = None
    kind: str = "event"
    severity: int | None = None
    type: str | None = None
    dataset: str | None = None
    provider: str | None = None
    risk_score: float | None = None


class ECSThreatIntel(BaseModel):
    """Threat intelligence enrichment context."""
    matched: bool = False
    ioc_type: str | None = None
    ioc_value: str | None = None
    threat_score: float | None = None
    source: str | None = None
    malware_family: str | None = None


class ECSCyberNest(BaseModel):
    """CyberNest-specific metadata added during pipeline processing."""
    event_id: str | None = None
    parser_name: str | None = None
    parse_status: str = "success"
    parse_time: str | None = None
    parse_duration_ms: float | None = None
    parser_version: str = "1.0.0"
    source_name: str | None = None
    agent_id: str | None = None
    ingested_at: str | None = None


class CyberNestEvent(BaseModel):
    """Complete ECS-normalized event — the canonical data model for CyberNest.

    Every log that enters the platform is normalized into this structure.
    The parser converts raw logs → CyberNestEvent → Kafka → Elasticsearch.
    """
    timestamp: datetime = Field(alias="@timestamp", default_factory=datetime.utcnow)
    event: ECSEvent = Field(default_factory=ECSEvent)
    source: ECSSource = Field(default_factory=ECSSource)
    destination: ECSDestination = Field(default_factory=ECSDestination)
    user: ECSUser = Field(default_factory=ECSUser)
    process: ECSProcess = Field(default_factory=ECSProcess)
    host: ECSHost = Field(default_factory=ECSHost)
    network: ECSNetwork = Field(default_factory=ECSNetwork)
    file: ECSFile = Field(default_factory=ECSFile)
    rule: ECSRule = Field(default_factory=ECSRule)
    threat_intel: ECSThreatIntel = Field(default_factory=ECSThreatIntel)
    cybernest: ECSCyberNest = Field(default_factory=ECSCyberNest)
    agent: dict[str, Any] = Field(default_factory=dict)
    observer: dict[str, Any] = Field(default_factory=dict)
    cloud: dict[str, Any] = Field(default_factory=dict)
    dns: dict[str, Any] = Field(default_factory=dict)
    http: dict[str, Any] = Field(default_factory=dict)
    url: dict[str, Any] = Field(default_factory=dict)
    registry: dict[str, Any] = Field(default_factory=dict)
    winlog: dict[str, Any] = Field(default_factory=dict)
    log: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None
    tags: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    raw: str | None = None

    model_config = {"populate_by_name": True}

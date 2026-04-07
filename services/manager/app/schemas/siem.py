"""CyberNest — SIEM request/response schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field
from app.models.enums import Severity, AlertStatus, AgentStatus, LogSourceType


# ── Agent ──

class AgentRegister(BaseModel):
    hostname: str
    ip_address: str
    os_type: str
    os_version: str | None = None
    agent_version: str
    labels: dict | None = None
    group: str | None = None


class AgentResponse(BaseModel):
    id: uuid.UUID
    hostname: str
    ip_address: str
    os_type: str
    os_version: str | None
    agent_version: str
    status: AgentStatus
    group: str | None
    labels: dict | None
    last_seen: datetime | None
    cpu_usage: float | None
    memory_usage: float | None
    events_per_second: float | None
    registered_at: datetime

    model_config = {"from_attributes": True}


class AgentHeartbeat(BaseModel):
    agent_id: uuid.UUID
    cpu_usage: float | None = None
    memory_usage: float | None = None
    events_per_second: float | None = None


# ── Log Source ──

class LogSourceCreate(BaseModel):
    name: str
    description: str | None = None
    source_type: LogSourceType
    format: str = "auto"
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    agent_id: uuid.UUID | None = None


class LogSourceResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    source_type: LogSourceType
    format: str
    host: str | None
    port: int | None
    enabled: bool
    events_received: int
    last_event_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Log Ingestion ──

class LogIngest(BaseModel):
    raw: str
    source: str | None = None
    source_type: str | None = None  # windows, linux, network, cloud, application
    agent_id: uuid.UUID | None = None
    tags: list[str] | None = None


class LogIngestBatch(BaseModel):
    logs: list[LogIngest]


class LogIngestResponse(BaseModel):
    accepted: int
    rejected: int
    errors: list[str] | None = None


# ── Detection Rule ──

class RuleCreate(BaseModel):
    rule_id: str
    name: str
    description: str | None = None
    severity: Severity
    level: int = Field(default=5, ge=0, le=15)
    rule_type: str = "threshold"
    logic: dict
    sigma_yaml: str | None = None
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    group: str | None = None
    tags: list[str] | None = None
    author: str | None = None
    false_positive_notes: str | None = None


class RuleResponse(BaseModel):
    id: uuid.UUID
    rule_id: str
    name: str
    description: str | None
    severity: Severity
    level: int
    rule_type: str
    rule_format: str
    logic: dict
    mitre_tactics: list[str] | None
    mitre_techniques: list[str] | None
    group: str | None
    tags: list[str] | None
    author: str | None
    version: int
    enabled: bool
    total_hits: int
    last_hit_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class RuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: Severity | None = None
    level: int | None = None
    logic: dict | None = None
    enabled: bool | None = None
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    tags: list[str] | None = None


# ── Alert ──

class AlertResponse(BaseModel):
    id: uuid.UUID
    title: str
    description: str | None
    severity: Severity
    status: AlertStatus
    rule_id: str | None
    rule_name: str | None
    source_ip: str | None
    destination_ip: str | None
    hostname: str | None
    username: str | None
    process_name: str | None
    ioc_type: str | None
    ioc_value: str | None
    mitre_tactics: list[str] | None
    mitre_techniques: list[str] | None
    threat_intel: dict | None
    geo_data: dict | None
    event_count: int
    raw_log: str | None
    assignee_id: uuid.UUID | None
    incident_id: uuid.UUID | None
    created_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assignee_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None


# ── Search ──

class SearchQuery(BaseModel):
    q: str = ""
    index: str = "cybernest-events-*"
    from_time: str | None = None
    to_time: str | None = None
    filters: dict | None = None
    size: int = Field(default=100, le=10000)
    offset: int = 0
    sort_field: str = "@timestamp"
    sort_order: str = "desc"


class SearchResponse(BaseModel):
    total: int
    took_ms: int
    hits: list[dict]


# ── Dashboard ──

class DashboardStats(BaseModel):
    total_events_24h: int
    total_alerts_24h: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    active_agents: int
    total_agents: int
    active_incidents: int
    events_per_second: float
    top_attackers: list[dict]
    top_targets: list[dict]
    top_rules: list[dict]
    alert_trend: list[dict]
    mitre_coverage: dict

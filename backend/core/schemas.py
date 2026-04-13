"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


# ─── Auth ───

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    role: str = "analyst"


class UserResponse(BaseModel):
    id: str
    tenant_id: Optional[int] = None
    username: str
    email: str
    full_name: str = ""
    role: str
    is_active: bool
    mfa_enabled: bool = False
    last_login: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str
    totp_code: Optional[str] = None


class AuthTokens(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class RefreshRequest(BaseModel):
    refresh_token: str


# ─── Log Sources ───

class LogSourceCreate(BaseModel):
    name: str
    source_type: str
    host: Optional[str] = None
    port: Optional[int] = None
    config: dict = {}


class LogSourceResponse(BaseModel):
    id: int
    name: str
    source_type: str
    host: Optional[str] = None
    port: Optional[int] = None
    enabled: bool
    last_seen: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Events ───

class EventCreate(BaseModel):
    raw_log: str
    source_id: Optional[int] = None


class EventResponse(BaseModel):
    id: int
    timestamp: datetime
    source_id: Optional[int] = None
    severity: str
    category: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    hostname: Optional[str] = None
    message: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    raw_log: Optional[str] = None

    model_config = {"from_attributes": True}


class SearchRequest(BaseModel):
    q: str = ""
    from_time: Optional[str] = None
    to_time: Optional[str] = None
    size: int = 100
    source: Optional[str] = None


class SearchResult(BaseModel):
    total: int
    took_ms: int
    hits: list[dict]


# ─── Alerts ───

class AlertResponse(BaseModel):
    id: str
    tenant_id: Optional[int] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: str
    status: str
    title: str
    description: Optional[str] = None
    source: str = "siem"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    assigned_to: Optional[str] = None
    incident_id: Optional[str] = None
    tags: list[str] = []
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    observables: list[dict] = []
    raw_log: Optional[str] = None
    event_count: int = 1
    comment_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    assignee_id: Optional[str] = None


class AlertCommentCreate(BaseModel):
    content: str


class AlertComment(BaseModel):
    id: str
    alert_id: str
    user_id: str
    user_name: str
    content: str
    created_at: datetime


# ─── Rules ───

class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str = "medium"
    logic: dict = {}
    enabled: bool = True
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    tags: list[str] = []


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    logic: Optional[dict] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None


class RuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    severity: str
    enabled: bool
    rule_type: str = "siem"
    logic: dict = {}
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    tags: list[str] = []
    total_hits: int = 0
    match_count_24h: int = 0
    last_match: Optional[datetime] = None
    author: str = "system"
    created_at: datetime
    updated_at: Optional[datetime] = None


# ─── Incidents / Cases ───

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    assigned_to: Optional[str] = None
    alert_ids: list[int] = []
    tags: list[str] = []


class IncidentResponse(BaseModel):
    id: str
    tenant_id: Optional[int] = None
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    assignee_name: Optional[str] = None
    tags: list = []
    timeline: list = []
    alert_count: int = 0
    task_count: int = 0
    tasks_completed: int = 0
    observable_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list] = None
    severity: Optional[str] = None


# ─── Playbooks ───

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: str = "manual"
    trigger_conditions: dict = {}
    steps: list
    enabled: bool = True


class PlaybookResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_conditions: dict = {}
    steps: list = []
    enabled: bool = True
    status: str = "active"
    total_runs: int = 0
    successful_runs: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None


class PlaybookTrigger(BaseModel):
    playbook_id: str
    alert_id: Optional[str] = None
    incident_id: Optional[int] = None
    dry_run: bool = False


class PlaybookRunResponse(BaseModel):
    id: str
    playbook_id: str
    playbook_name: Optional[str] = None
    incident_id: Optional[str] = None
    status: str
    steps_completed: int = 0
    steps_total: int = 0
    step_results: list = []
    error_message: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None


# ─── Dashboard ───

class DashboardStats(BaseModel):
    total_events_24h: int = 0
    total_alerts_24h: int = 0
    total_alerts: int = 0
    open_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    active_incidents: int = 0
    active_agents: int = 0
    total_agents: int = 0
    online_agents: int = 0
    offline_agents: int = 0
    total_rules: int = 0
    active_rules: int = 0
    active_playbooks: int = 0
    open_cases: int = 0
    total_iocs: int = 0
    events_per_second: float = 0.0
    mttr_minutes: int = 0
    resolved_today: int = 0
    alert_trend: list[dict] = []
    alerts_trend_24h: list[dict] = []
    alerts_by_severity: list[dict] = []
    top_attackers: list[dict] = []
    top_rules: list[dict] = []
    mitre_coverage: dict = {}
    recent_alerts: list[AlertResponse] = []


# ─── Threat Intel ───

class ThreatLookupResult(BaseModel):
    query: str
    type: str
    found: bool
    value: Optional[str] = None
    sources: list[dict] = []
    results: list[dict] = []


class IOCResponse(BaseModel):
    id: str
    type: str
    value: str
    severity: str = "medium"
    confidence: int = 50
    source: str = "manual"
    tags: list[str] = []
    first_seen: datetime
    last_seen: datetime
    is_active: bool = True
    sightings: int = 0
    related_alerts: int = 0


# ─── Alert Stats ───

class AlertStats(BaseModel):
    total: int
    by_severity: dict
    by_status: dict
    trend: list[dict] = []


class RuleStats(BaseModel):
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    matches_24h: int = 0
    top_firing_rules: list[dict] = []
    rules_by_severity: dict = {}

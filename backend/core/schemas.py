"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr


# ─── Auth ───

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ─── SIEM ───

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
    host: Optional[str]
    port: Optional[int]
    enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class EventCreate(BaseModel):
    raw_log: str
    source_id: Optional[int] = None
    severity: str = "info"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    message: Optional[str] = None


class EventResponse(BaseModel):
    id: int
    timestamp: datetime
    source_id: Optional[int]
    severity: str
    category: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    hostname: Optional[str]
    message: Optional[str]
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]

    model_config = {"from_attributes": True}


class EventQuery(BaseModel):
    query: Optional[str] = None
    severity: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = 100
    offset: int = 0


class AlertResponse(BaseModel):
    id: int
    rule_id: Optional[int]
    severity: str
    status: str
    title: str
    description: Optional[str]
    ioc_data: dict
    assigned_to: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None


class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    severity: str = "medium"
    logic: dict
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None


# ─── SOAR ───

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    assigned_to: Optional[str] = None
    alert_ids: list[int] = []


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    assigned_to: Optional[str]
    tags: list
    timeline: list
    created_at: datetime

    model_config = {"from_attributes": True}


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[list] = None


class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    trigger_type: Optional[str]
    steps: list
    enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class PlaybookRunResponse(BaseModel):
    id: int
    playbook_id: int
    incident_id: Optional[int]
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    step_results: list

    model_config = {"from_attributes": True}


# ─── Dashboard ───

class DashboardStats(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    active_incidents: int
    playbook_runs_today: int
    events_per_hour: list[dict]
    alerts_by_severity: dict
    top_source_ips: list[dict]
    recent_alerts: list[AlertResponse]

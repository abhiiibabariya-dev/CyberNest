"""CyberNest — SOAR request/response schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field
from app.models.enums import Severity, IncidentStatus, PlaybookStatus, IOCType


# ── Incident / Case ──

class IncidentCreate(BaseModel):
    title: str
    description: str | None = None
    severity: Severity
    template: str | None = None
    assignee_id: uuid.UUID | None = None
    tags: list[str] | None = None
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None
    alert_ids: list[uuid.UUID] | None = None


class IncidentResponse(BaseModel):
    id: uuid.UUID
    case_id: str
    title: str
    description: str | None
    severity: Severity
    status: IncidentStatus
    template: str | None
    assignee_id: uuid.UUID | None
    tags: list[str] | None
    mitre_tactics: list[str] | None
    mitre_techniques: list[str] | None
    affected_assets: list[str] | None
    affected_users: list[str] | None
    timeline: list | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None

    model_config = {"from_attributes": True}


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: Severity | None = None
    status: IncidentStatus | None = None
    assignee_id: uuid.UUID | None = None
    tags: list[str] | None = None


# ── Case Task ──

class CaseTaskCreate(BaseModel):
    title: str
    description: str | None = None
    assignee_id: uuid.UUID | None = None
    due_date: datetime | None = None


class CaseTaskResponse(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    title: str
    description: str | None
    status: str
    assignee_id: uuid.UUID | None
    due_date: datetime | None
    order: int
    created_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class CaseTaskUpdate(BaseModel):
    title: str | None = None
    status: str | None = None
    assignee_id: uuid.UUID | None = None


# ── Observable / IOC ──

class ObservableCreate(BaseModel):
    ioc_type: IOCType
    value: str
    description: str | None = None
    tags: list[str] | None = None
    tlp: str = "amber"


class ObservableResponse(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    ioc_type: IOCType
    value: str
    description: str | None
    tags: list[str] | None
    is_ioc: bool
    tlp: str
    threat_score: float | None
    enrichment: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Playbook ──

class PlaybookCreate(BaseModel):
    name: str
    description: str | None = None
    trigger_type: str = "manual"
    trigger_conditions: dict | None = None
    steps: list[dict]
    yaml_definition: str | None = None
    tags: list[str] | None = None


class PlaybookResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    version: int
    enabled: bool
    trigger_type: str
    trigger_conditions: dict | None
    steps: list[dict]
    author: str | None
    tags: list[str] | None
    total_runs: int
    successful_runs: int
    avg_duration_ms: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PlaybookTrigger(BaseModel):
    playbook_id: uuid.UUID
    alert_id: uuid.UUID | None = None
    incident_id: uuid.UUID | None = None
    input_data: dict | None = None
    dry_run: bool = False


class PlaybookRunResponse(BaseModel):
    id: uuid.UUID
    playbook_id: uuid.UUID
    incident_id: uuid.UUID | None
    alert_id: uuid.UUID | None
    status: PlaybookStatus
    is_dry_run: bool
    input_data: dict | None
    step_results: list | None
    error_message: str | None
    started_at: datetime
    completed_at: datetime | None
    duration_ms: int | None

    model_config = {"from_attributes": True}

"""CyberNest — SOAR data models (Incidents, Playbooks, Tasks, Observables)."""

import uuid
from datetime import datetime

from sqlalchemy import (
    String, Integer, Boolean, DateTime, Text, Float,
    ForeignKey, Index, BigInteger,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB

from app.core.database import Base
from app.models.enums import Severity, IncidentStatus, PlaybookStatus, IOCType


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_assignee_id", "assignee_id"),
        Index("ix_incidents_created_at", "created_at"),
        {"schema": "soar"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)  # CN-INC-00001
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(default=IncidentStatus.OPEN)
    template: Mapped[str | None] = mapped_column(String(128), nullable=True)  # ransomware_ir, phishing_ir, etc.

    # Assignment
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("auth.users.id", ondelete="SET NULL"), nullable=True)

    # Classification
    classification: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    mitre_tactics: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    mitre_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Impact
    affected_assets: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    affected_users: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Timeline (JSON array of timeline events)
    timeline: Mapped[list | None] = mapped_column(JSONB, default=list)

    # SLA
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_to_resolve_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    assignee: Mapped["User | None"] = relationship(back_populates="assigned_cases", foreign_keys=[assignee_id])
    tasks: Mapped[list["CaseTask"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    observables: Mapped[list["Observable"]] = relationship(back_populates="incident", cascade="all, delete-orphan")
    playbook_runs: Mapped[list["PlaybookRun"]] = relationship(back_populates="incident", cascade="all, delete-orphan")


class CaseTask(Base):
    __tablename__ = "case_tasks"
    __table_args__ = (
        Index("ix_case_tasks_incident_id", "incident_id"),
        Index("ix_case_tasks_assignee_id", "assignee_id"),
        {"schema": "soar"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("soar.incidents.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending, in_progress, completed
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("auth.users.id", ondelete="SET NULL"), nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    incident: Mapped["Incident"] = relationship(back_populates="tasks")


class Observable(Base):
    __tablename__ = "observables"
    __table_args__ = (
        Index("ix_observables_incident_id", "incident_id"),
        Index("ix_observables_ioc_type", "ioc_type"),
        Index("ix_observables_value", "value"),
        {"schema": "soar"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("soar.incidents.id", ondelete="CASCADE"))
    ioc_type: Mapped[IOCType] = mapped_column(nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    is_ioc: Mapped[bool] = mapped_column(Boolean, default=True)
    sighted: Mapped[bool] = mapped_column(Boolean, default=False)

    # Threat intel enrichment
    tlp: Mapped[str] = mapped_column(String(16), default="amber")  # white, green, amber, red
    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    enrichment: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="observables")


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (
        Index("ix_playbooks_enabled", "enabled"),
        {"schema": "soar"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Trigger conditions
    trigger_type: Mapped[str] = mapped_column(String(32), default="manual")  # manual, alert, schedule
    trigger_conditions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Steps definition
    steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    yaml_definition: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Metadata
    author: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Stats
    total_runs: Mapped[int] = mapped_column(Integer, default=0)
    successful_runs: Mapped[int] = mapped_column(Integer, default=0)
    avg_duration_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    runs: Mapped[list["PlaybookRun"]] = relationship(back_populates="playbook", cascade="all, delete-orphan")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (
        Index("ix_playbook_runs_playbook_id", "playbook_id"),
        Index("ix_playbook_runs_status", "status"),
        Index("ix_playbook_runs_started_at", "started_at"),
        {"schema": "soar"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    playbook_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("soar.playbooks.id", ondelete="CASCADE"))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("soar.incidents.id", ondelete="SET NULL"), nullable=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("siem.alerts.id", ondelete="SET NULL"), nullable=True)
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("auth.users.id", ondelete="SET NULL"), nullable=True)

    status: Mapped[PlaybookStatus] = mapped_column(default=PlaybookStatus.PENDING)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=False)

    # Input context
    input_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Execution results
    step_results: Mapped[list | None] = mapped_column(JSONB, default=list)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Timing
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    playbook: Mapped["Playbook"] = relationship(back_populates="runs")
    incident: Mapped["Incident | None"] = relationship(back_populates="playbook_runs")


# Forward ref import
from app.models.auth import User  # noqa: E402, F401

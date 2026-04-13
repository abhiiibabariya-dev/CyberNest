"""CyberNest Multi-Tenant Data Models."""
from datetime import datetime, timezone
import enum, secrets
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, Enum, JSON, UniqueConstraint, Index
)
from sqlalchemy.orm import relationship
from core.database import Base

class Severity(str, enum.Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"

class AlertStatus(str, enum.Enum):
    NEW = "new"; ACKNOWLEDGED = "acknowledged"; INVESTIGATING = "investigating"
    RESOLVED = "resolved"; FALSE_POSITIVE = "false_positive"

class IncidentStatus(str, enum.Enum):
    OPEN = "open"; IN_PROGRESS = "in_progress"; CONTAINED = "contained"
    ERADICATED = "eradicated"; RECOVERED = "recovered"; CLOSED = "closed"

class PlaybookStatus(str, enum.Enum):
    IDLE = "idle"; RUNNING = "running"; COMPLETED = "completed"; FAILED = "failed"

class TenantPlan(str, enum.Enum):
    TRIAL = "trial"; STARTER = "starter"; BUSINESS = "business"; ENTERPRISE = "enterprise"

class UserRole(str, enum.Enum):
    SUPER_ADMIN = "super_admin"; TENANT_ADMIN = "tenant_admin"
    ANALYST = "analyst"; VIEWER = "viewer"

class Tenant(Base):
    __tablename__ = "tenants"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    slug          = Column(String(64), unique=True, nullable=False)
    name          = Column(String(255), nullable=False)
    plan          = Column(Enum(TenantPlan), default=TenantPlan.TRIAL)
    is_active     = Column(Boolean, default=True)
    settings      = Column(JSON, default=dict)
    ingest_token  = Column(String(64), unique=True, default=lambda: secrets.token_urlsafe(32))
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    trial_ends_at = Column(DateTime, nullable=True)
    users           = relationship("User",          back_populates="tenant", cascade="all, delete-orphan")
    log_sources     = relationship("LogSource",     back_populates="tenant", cascade="all, delete-orphan")
    events          = relationship("Event",         back_populates="tenant", cascade="all, delete-orphan")
    alerts          = relationship("Alert",         back_populates="tenant", cascade="all, delete-orphan")
    incidents       = relationship("Incident",      back_populates="tenant", cascade="all, delete-orphan")
    playbooks       = relationship("Playbook",      back_populates="tenant", cascade="all, delete-orphan")
    detection_rules = relationship("DetectionRule", back_populates="tenant", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "username", name="uq_tenant_username"),
        Index("ix_users_tenant", "tenant_id"),
    )
    id              = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id       = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    username        = Column(String(100), nullable=False)
    email           = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role            = Column(Enum(UserRole), default=UserRole.ANALYST)
    is_active       = Column(Boolean, default=True)
    last_login      = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tenant = relationship("Tenant", back_populates="users")

class LogSource(Base):
    __tablename__ = "log_sources"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tenant_source_name"),
        Index("ix_log_sources_tenant", "tenant_id"),
    )
    id          = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id   = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name        = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False)
    host        = Column(String(255))
    port        = Column(Integer)
    enabled     = Column(Boolean, default=True)
    config      = Column(JSON, default=dict)
    last_seen   = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tenant = relationship("Tenant", back_populates="log_sources")
    events = relationship("Event",  back_populates="source")

class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_tenant_time", "tenant_id", "timestamp"),
        Index("ix_events_tenant_src",  "tenant_id", "src_ip"),
    )
    id              = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id       = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    timestamp       = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_id       = Column(Integer, ForeignKey("log_sources.id"), nullable=True)
    raw_log         = Column(Text, nullable=False)
    parsed          = Column(JSON, default=dict)
    severity        = Column(Enum(Severity), default=Severity.INFO)
    category        = Column(String(100))
    src_ip          = Column(String(45))
    dst_ip          = Column(String(45))
    src_port        = Column(Integer)
    dst_port        = Column(Integer)
    protocol        = Column(String(20))
    user            = Column(String(255))
    hostname        = Column(String(255))
    message         = Column(Text)
    mitre_tactic    = Column(String(100))
    mitre_technique = Column(String(100))
    tenant = relationship("Tenant",    back_populates="events")
    source = relationship("LogSource", back_populates="events")

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tenant_rule_name"),
        Index("ix_detection_rules_tenant", "tenant_id"),
    )
    id              = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id       = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name            = Column(String(255), nullable=False)
    description     = Column(Text)
    severity        = Column(Enum(Severity), default=Severity.MEDIUM)
    enabled         = Column(Boolean, default=True)
    logic           = Column(JSON, nullable=False)
    mitre_tactic    = Column(String(100))
    mitre_technique = Column(String(100))
    is_global       = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at      = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))
    tenant = relationship("Tenant", back_populates="detection_rules")
    alerts = relationship("Alert",  back_populates="rule")

class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_tenant_time",     "tenant_id", "created_at"),
        Index("ix_alerts_tenant_status",   "tenant_id", "status"),
        Index("ix_alerts_tenant_severity", "tenant_id", "severity"),
    )
    id               = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id        = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_id          = Column(Integer, ForeignKey("detection_rules.id"), nullable=True)
    severity         = Column(Enum(Severity), nullable=False)
    status           = Column(Enum(AlertStatus), default=AlertStatus.NEW)
    title            = Column(String(500), nullable=False)
    description      = Column(Text)
    source_event_ids = Column(JSON, default=list)
    ioc_data         = Column(JSON, default=dict)
    assigned_to      = Column(String(255))
    created_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at       = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))
    incident_id      = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    tenant   = relationship("Tenant",        back_populates="alerts")
    rule     = relationship("DetectionRule", back_populates="alerts")
    incident = relationship("Incident",      back_populates="alerts")

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_tenant_status", "tenant_id", "status"),)
    id          = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id   = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    title       = Column(String(500), nullable=False)
    description = Column(Text)
    severity    = Column(Enum(Severity), nullable=False)
    status      = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    assigned_to = Column(String(255))
    tags        = Column(JSON, default=list)
    timeline    = Column(JSON, default=list)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))
    closed_at   = Column(DateTime, nullable=True)
    tenant        = relationship("Tenant",      back_populates="incidents")
    alerts        = relationship("Alert",       back_populates="incident")
    playbook_runs = relationship("PlaybookRun", back_populates="incident")

class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tenant_playbook_name"),
        Index("ix_playbooks_tenant", "tenant_id"),
    )
    id                 = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id          = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name               = Column(String(255), nullable=False)
    description        = Column(Text)
    trigger_type       = Column(String(50))
    trigger_conditions = Column(JSON, default=dict)
    steps              = Column(JSON, nullable=False)
    enabled            = Column(Boolean, default=True)
    is_global          = Column(Boolean, default=False)
    created_at         = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tenant = relationship("Tenant",      back_populates="playbooks")
    runs   = relationship("PlaybookRun", back_populates="playbook")

class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id    = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    playbook_id  = Column(Integer, ForeignKey("playbooks.id"), nullable=False)
    incident_id  = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    status       = Column(Enum(PlaybookStatus), default=PlaybookStatus.RUNNING)
    started_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    step_results = Column(JSON, default=list)
    error        = Column(Text, nullable=True)
    playbook = relationship("Playbook", back_populates="runs")
    incident = relationship("Incident", back_populates="playbook_runs")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_tenant_time", "tenant_id", "created_at"),)
    id          = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id   = Column(Integer, nullable=True)
    user_id     = Column(Integer, nullable=True)
    username    = Column(String(100))
    action      = Column(String(100), nullable=False)
    resource    = Column(String(100))
    resource_id = Column(Integer)
    details     = Column(JSON, default=dict)
    ip_address  = Column(String(45))
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

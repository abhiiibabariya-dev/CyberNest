"""Database models for CyberNest."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship
import enum

from core.database import Base


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class PlaybookStatus(str, enum.Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ─── SIEM Models ───


class LogSource(Base):
    __tablename__ = "log_sources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)
    source_type = Column(String(50), nullable=False)  # syslog, api, file, agent
    host = Column(String(255))
    port = Column(Integer)
    enabled = Column(Boolean, default=True)
    config = Column(JSON, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    events = relationship("Event", back_populates="source")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_id = Column(Integer, ForeignKey("log_sources.id"))
    raw_log = Column(Text, nullable=False)
    parsed = Column(JSON, default=dict)
    severity = Column(Enum(Severity), default=Severity.INFO)
    category = Column(String(100))
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(20))
    user = Column(String(255))
    hostname = Column(String(255))
    message = Column(Text)
    mitre_tactic = Column(String(100))
    mitre_technique = Column(String(100))

    source = relationship("LogSource", back_populates="events")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    enabled = Column(Boolean, default=True)
    logic = Column(JSON, nullable=False)  # Rule conditions
    mitre_tactic = Column(String(100))
    mitre_technique = Column(String(100))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))

    alerts = relationship("Alert", back_populates="rule")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("detection_rules.id"))
    severity = Column(Enum(Severity), nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    source_event_ids = Column(JSON, default=list)
    ioc_data = Column(JSON, default=dict)  # IP, hash, domain, etc.
    assigned_to = Column(String(255))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))

    rule = relationship("DetectionRule", back_populates="alerts")
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    incident = relationship("Incident", back_populates="alerts")


# ─── SOAR Models ───


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(Severity), nullable=False)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    assigned_to = Column(String(255))
    tags = Column(JSON, default=list)
    timeline = Column(JSON, default=list)  # List of timestamped actions
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))
    closed_at = Column(DateTime, nullable=True)

    alerts = relationship("Alert", back_populates="incident")
    playbook_runs = relationship("PlaybookRun", back_populates="incident")


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    trigger_type = Column(String(50))  # manual, alert, schedule
    trigger_conditions = Column(JSON, default=dict)
    steps = Column(JSON, nullable=False)  # Ordered list of actions
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    runs = relationship("PlaybookRun", back_populates="playbook")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id"))
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    status = Column(Enum(PlaybookStatus), default=PlaybookStatus.RUNNING)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    step_results = Column(JSON, default=list)
    error = Column(Text, nullable=True)

    playbook = relationship("Playbook", back_populates="runs")
    incident = relationship("Incident", back_populates="playbook_runs")


# ─── Auth ───


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

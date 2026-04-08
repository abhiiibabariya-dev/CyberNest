"""
CyberNest Manager -- Full SQLAlchemy ORM models matching init.sql schema.

All tables: users, agents, rules, alerts, cases, case_tasks, case_observables,
case_comments, case_attachments, playbooks, playbook_executions,
threat_intel_iocs, threat_intel_feeds, assets, notification_channels, audit_log.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from manager.db.database import Base


# ---------------------------------------------------------------------------
# Enum types matching PostgreSQL enums in init.sql
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    super_admin = "super_admin"
    admin = "admin"
    soc_lead = "soc_lead"
    analyst = "analyst"
    readonly = "readonly"


class AgentStatusEnum(str, enum.Enum):
    online = "online"
    offline = "offline"
    degraded = "degraded"


class AlertSeverityEnum(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatusEnum(str, enum.Enum):
    new = "new"
    in_progress = "in_progress"
    resolved = "resolved"
    false_positive = "false_positive"
    escalated = "escalated"


class CaseSeverityEnum(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class CaseStatusEnum(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    closed = "closed"


class TLPLevel(str, enum.Enum):
    white = "white"
    green = "green"
    amber = "amber"
    red = "red"


class PlaybookExecStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    success = "success"
    failure = "failure"
    cancelled = "cancelled"
    timed_out = "timed_out"


class IOCType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash_md5 = "hash_md5"
    hash_sha1 = "hash_sha1"
    hash_sha256 = "hash_sha256"
    email = "email"
    filename = "filename"
    registry_key = "registry_key"
    cve = "cve"
    ja3 = "ja3"
    cidr = "cidr"


class FeedType(str, enum.Enum):
    stix = "stix"
    csv = "csv"
    json = "json"
    misp = "misp"
    otx = "otx"
    abuse_ipdb = "abuse_ipdb"
    custom = "custom"


class AssetCriticality(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ChannelType(str, enum.Enum):
    email = "email"
    slack = "slack"
    webhook = "webhook"
    pagerduty = "pagerduty"
    teams = "teams"
    telegram = "telegram"
    syslog = "syslog"


class ObservableDataType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    email = "email"
    filename = "filename"
    registry = "registry"
    other = "other"


class TaskStatusEnum(str, enum.Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    cancelled = "cancelled"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", create_type=False),
        nullable=False,
        default=UserRole.analyst,
    )
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    # Relationships
    assigned_alerts: Mapped[list[Alert]] = relationship(
        "Alert", back_populates="assignee_user", foreign_keys="Alert.assignee"
    )
    assigned_cases: Mapped[list[Case]] = relationship(
        "Case", back_populates="assignee_user", foreign_keys="Case.assignee"
    )
    created_rules: Mapped[list[Rule]] = relationship(
        "Rule", back_populates="creator", foreign_keys="Rule.created_by"
    )
    case_comments: Mapped[list[CaseComment]] = relationship(
        "CaseComment", back_populates="user"
    )
    audit_entries: Mapped[list[AuditLog]] = relationship(
        "AuditLog", back_populates="user"
    )


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    os: Mapped[str] = mapped_column(String(50), nullable=False)
    os_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(20), nullable=True)
    version: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[AgentStatusEnum] = mapped_column(
        Enum(AgentStatusEnum, name="agent_status", create_type=False),
        nullable=False,
        default=AgentStatusEnum.offline,
    )
    api_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    enrolled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    config_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    tags: Mapped[list] = mapped_column(ARRAY(Text), default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    # Relationships
    alerts: Mapped[list[Alert]] = relationship("Alert", back_populates="agent_rel")


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    rule_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[list] = mapped_column(ARRAY(Text), default=list)
    content_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    sigma_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    hit_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    false_positive_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    # Relationships
    creator: Mapped[User | None] = relationship(
        "User", back_populates="created_rules", foreign_keys=[created_by]
    )
    alerts: Mapped[list[Alert]] = relationship("Alert", back_populates="rule_rel")


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[CaseSeverityEnum] = mapped_column(
        Enum(CaseSeverityEnum, name="case_severity", create_type=False),
        nullable=False,
        default=CaseSeverityEnum.medium,
    )
    status: Mapped[CaseStatusEnum] = mapped_column(
        Enum(CaseStatusEnum, name="case_status", create_type=False),
        nullable=False,
        default=CaseStatusEnum.open,
    )
    assignee: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    tags: Mapped[list] = mapped_column(ARRAY(Text), default=list)
    tlp: Mapped[TLPLevel] = mapped_column(
        Enum(TLPLevel, name="tlp_level", create_type=False),
        nullable=False,
        default=TLPLevel.amber,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    # Relationships
    assignee_user: Mapped[User | None] = relationship(
        "User", back_populates="assigned_cases", foreign_keys=[assignee]
    )
    alerts: Mapped[list[Alert]] = relationship("Alert", back_populates="case_rel")
    tasks: Mapped[list[CaseTask]] = relationship(
        "CaseTask", back_populates="case", cascade="all, delete-orphan"
    )
    observables: Mapped[list[CaseObservable]] = relationship(
        "CaseObservable", back_populates="case", cascade="all, delete-orphan"
    )
    comments: Mapped[list[CaseComment]] = relationship(
        "CaseComment", back_populates="case", cascade="all, delete-orphan"
    )
    attachments: Mapped[list[CaseAttachment]] = relationship(
        "CaseAttachment", back_populates="case", cascade="all, delete-orphan"
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rules.id", ondelete="SET NULL"), nullable=True
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    severity: Mapped[AlertSeverityEnum] = mapped_column(
        Enum(AlertSeverityEnum, name="alert_severity", create_type=False),
        nullable=False,
        default=AlertSeverityEnum.medium,
    )
    status: Mapped[AlertStatusEnum] = mapped_column(
        Enum(AlertStatusEnum, name="alert_status", create_type=False),
        nullable=False,
        default=AlertStatusEnum.new,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    parsed_event: Mapped[dict] = mapped_column(JSONB, default=dict)
    mitre_tactic: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_subtechnique: Mapped[str | None] = mapped_column(String(100), nullable=True)
    assignee: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    # Relationships
    rule_rel: Mapped[Rule | None] = relationship("Rule", back_populates="alerts")
    agent_rel: Mapped[Agent | None] = relationship("Agent", back_populates="alerts")
    assignee_user: Mapped[User | None] = relationship(
        "User", back_populates="assigned_alerts", foreign_keys=[assignee]
    )
    case_rel: Mapped[Case | None] = relationship("Case", back_populates="alerts")
    playbook_executions: Mapped[list[PlaybookExecution]] = relationship(
        "PlaybookExecution", back_populates="alert_rel"
    )


class CaseTask(Base):
    __tablename__ = "case_tasks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[TaskStatusEnum] = mapped_column(
        Enum(TaskStatusEnum, name="task_status", create_type=False),
        nullable=False,
        default=TaskStatusEnum.pending,
    )
    assignee: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    due_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    case: Mapped[Case] = relationship("Case", back_populates="tasks")


class CaseObservable(Base):
    __tablename__ = "case_observables"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    data_type: Mapped[ObservableDataType] = mapped_column(
        Enum(ObservableDataType, name="observable_data_type", create_type=False),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_ioc: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tlp: Mapped[TLPLevel] = mapped_column(
        Enum(TLPLevel, name="tlp_level", create_type=False),
        nullable=False,
        default=TLPLevel.amber,
    )
    tags: Mapped[list] = mapped_column(ARRAY(Text), default=list)
    sighted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    case: Mapped[Case] = relationship("Case", back_populates="observables")


class CaseComment(Base):
    __tablename__ = "case_comments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    case: Mapped[Case] = relationship("Case", back_populates="comments")
    user: Mapped[User] = relationship("User", back_populates="case_comments")


class CaseAttachment(Base):
    __tablename__ = "case_attachments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    filename: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str] = mapped_column(
        String(255), nullable=False, default="application/octet-stream"
    )
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    case: Mapped[Case] = relationship("Case", back_populates="attachments")


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False, default="manual")
    trigger_conditions: Mapped[dict] = mapped_column(JSONB, default=dict)
    content_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    run_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )

    executions: Mapped[list[PlaybookExecution]] = relationship(
        "PlaybookExecution", back_populates="playbook", cascade="all, delete-orphan"
    )


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    triggered_by: Mapped[str] = mapped_column(String(100), nullable=False, default="manual")
    trigger_context: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[PlaybookExecStatus] = mapped_column(
        Enum(PlaybookExecStatus, name="playbook_exec_status", create_type=False),
        nullable=False,
        default=PlaybookExecStatus.pending,
    )
    steps_log: Mapped[list] = mapped_column(JSONB, default=list)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    playbook: Mapped[Playbook] = relationship("Playbook", back_populates="executions")
    alert_rel: Mapped[Alert | None] = relationship("Alert", back_populates="playbook_executions")


class ThreatIntelIOC(Base):
    __tablename__ = "threat_intel_iocs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ioc_type: Mapped[IOCType] = mapped_column(
        Enum(IOCType, name="ioc_type", create_type=False), nullable=False
    )
    value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    tags: Mapped[list] = mapped_column(ARRAY(Text), default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    hit_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )


class ThreatIntelFeed(Base):
    __tablename__ = "threat_intel_feeds"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    feed_type: Mapped[FeedType] = mapped_column(
        Enum(FeedType, name="feed_type", create_type=False), nullable=False
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    api_key: Mapped[str | None] = mapped_column(String(500), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_fetched: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fetch_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    config_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    os: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(AssetCriticality, name="asset_criticality", create_type=False),
        nullable=False,
        default=AssetCriticality.medium,
    )
    role: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tags: Mapped[list] = mapped_column(ARRAY(Text), default=list)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    channel_type: Mapped[ChannelType] = mapped_column(
        Enum(ChannelType, name="channel_type", create_type=False), nullable=False
    )
    config_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=_utcnow
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped[User | None] = relationship("User", back_populates="audit_entries")

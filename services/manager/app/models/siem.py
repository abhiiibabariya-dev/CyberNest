"""CyberNest — SIEM data models (Events, Alerts, Rules, Log Sources, Agents)."""

import uuid
from datetime import datetime

from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, BigInteger,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY, INET, JSONB

from app.core.database import Base
from app.models.enums import Severity, AlertStatus, AgentStatus, LogSourceType


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        Index("ix_agents_hostname", "hostname"),
        Index("ix_agents_status", "status"),
        Index("ix_agents_last_seen", "last_seen"),
        {"schema": "siem"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    os_type: Mapped[str] = mapped_column(String(32), nullable=False)  # windows, linux, macos
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[AgentStatus] = mapped_column(default=AgentStatus.PENDING)

    # Authentication
    auth_key: Mapped[str] = mapped_column(String(255), nullable=False)
    cert_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Configuration
    config: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    labels: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    group: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Health
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cpu_usage: Mapped[float | None] = mapped_column(Float, nullable=True)
    memory_usage: Mapped[float | None] = mapped_column(Float, nullable=True)
    events_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Timestamps
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    log_source: Mapped["LogSource | None"] = relationship(back_populates="agent", uselist=False)


class LogSource(Base):
    __tablename__ = "log_sources"
    __table_args__ = (
        Index("ix_log_sources_source_type", "source_type"),
        Index("ix_log_sources_enabled", "enabled"),
        {"schema": "siem"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_type: Mapped[LogSourceType] = mapped_column(nullable=False)
    format: Mapped[str] = mapped_column(String(32), default="auto")  # syslog, cef, json, xml, etc.
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)  # tcp, udp, tls
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Agent link (for agent-based sources)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("siem.agents.id", ondelete="SET NULL"), nullable=True)

    # Stats
    events_received: Mapped[int] = mapped_column(BigInteger, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_count: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    agent: Mapped["Agent | None"] = relationship(back_populates="log_source")


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_rules_enabled", "enabled"),
        Index("ix_rules_severity", "severity"),
        Index("ix_rules_rule_id", "rule_id", unique=True),
        {"schema": "siem"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)  # e.g., CN-100001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(nullable=False)
    level: Mapped[int] = mapped_column(Integer, default=5)  # 0-15 Wazuh-style

    # Rule definition
    rule_type: Mapped[str] = mapped_column(String(32), default="threshold")  # threshold, frequency, sequence, aggregation, sigma
    rule_format: Mapped[str] = mapped_column(String(16), default="yaml")  # yaml, sigma, xml
    logic: Mapped[dict] = mapped_column(JSONB, nullable=False)  # Rule conditions
    sigma_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)  # Raw Sigma YAML

    # MITRE ATT&CK mapping
    mitre_tactics: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    mitre_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    mitre_subtechniques: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Metadata
    group: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    references: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    author: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    false_positive_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Stats
    total_hits: Mapped[int] = mapped_column(BigInteger, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_created_at", "created_at"),
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_src_ip", "source_ip"),
        Index("ix_alerts_assignee_id", "assignee_id"),
        {"schema": "siem"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(nullable=False)
    status: Mapped[AlertStatus] = mapped_column(default=AlertStatus.NEW)

    # Source
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("siem.agents.id", ondelete="SET NULL"), nullable=True)

    # Event context
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # IOC data
    ioc_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ioc_value: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # MITRE
    mitre_tactics: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    mitre_techniques: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Enrichment
    threat_intel: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    geo_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    asset_info: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Related events (ES document IDs)
    event_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Assignment
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("auth.users.id", ondelete="SET NULL"), nullable=True)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("soar.incidents.id", ondelete="SET NULL"), nullable=True)

    # SLA
    time_to_detect_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    time_to_respond_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

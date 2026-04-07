"""CyberNest — Asset & CMDB models."""

import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB

from app.core.database import Base
from app.models.enums import AssetCriticality


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_hostname", "hostname"),
        Index("ix_assets_ip_address", "ip_address"),
        Index("ix_assets_criticality", "criticality"),
        {"schema": "assets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    os_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Classification
    asset_type: Mapped[str | None] = mapped_column(String(64), nullable=True)  # server, workstation, router, etc.
    criticality: Mapped[AssetCriticality] = mapped_column(default=AssetCriticality.MEDIUM)
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    group: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Network
    subnet: Mapped[str | None] = mapped_column(String(18), nullable=True)
    open_ports: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    services: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Risk
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)

    # Agent link
    agent_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("siem.agents.id", ondelete="SET NULL"), nullable=True)

    # Discovery
    discovered_by: Mapped[str | None] = mapped_column(String(32), nullable=True)  # agent, nmap, manual
    is_managed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vulns_asset_id", "asset_id"),
        Index("ix_vulns_cve_id", "cve_id"),
        Index("ix_vulns_severity", "severity"),
        {"schema": "assets"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.assets.id", ondelete="CASCADE"))
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # critical, high, medium, low
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    solution: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner: Mapped[str | None] = mapped_column(String(64), nullable=True)  # openvas, nessus, qualys
    is_patched: Mapped[bool] = mapped_column(Boolean, default=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

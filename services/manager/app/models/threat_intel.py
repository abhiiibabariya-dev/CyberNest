"""CyberNest — Threat Intelligence models (IOC database, feeds)."""

import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Float, Boolean, DateTime, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB

from app.core.database import Base
from app.models.enums import IOCType


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"
    __table_args__ = (
        Index("ix_feeds_enabled", "enabled"),
        {"schema": "threat_intel"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    feed_type: Mapped[str] = mapped_column(String(32), nullable=False)  # taxii, csv, stix, json, api
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    api_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    refresh_interval: Mapped[int] = mapped_column(Integer, default=3600)  # seconds
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    last_fetch_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class IOCEntry(Base):
    __tablename__ = "ioc_entries"
    __table_args__ = (
        Index("ix_ioc_type", "ioc_type"),
        Index("ix_ioc_value", "value"),
        Index("ix_ioc_type_value", "ioc_type", "value", unique=True),
        Index("ix_ioc_expires_at", "expires_at"),
        {"schema": "threat_intel"},
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_type: Mapped[IOCType] = mapped_column(nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scoring
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    confidence: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    source_count: Mapped[int] = mapped_column(Integer, default=1)
    sources: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)

    # Classification
    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)  # malware, c2, phishing, etc.
    malware_family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    tlp: Mapped[str] = mapped_column(String(16), default="amber")

    # Context
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Enrichment
    enrichment: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    whois_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    geo_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

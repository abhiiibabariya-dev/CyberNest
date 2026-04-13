#!/usr/bin/env python3
"""
CyberNest Update Script
Run this from your CyberNest repo root:
    python apply_cybernest_updates.py

It writes every updated file into the correct location.
"""

import os, sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend")

def write(path, content):
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  ✓ {path}")

print("CyberNest — applying all updates...\n")

# ─────────────────────────────────────────────────────────────
# backend/core/config.py
# ─────────────────────────────────────────────────────────────
write("backend/core/config.py", '''"""Application configuration."""
from pydantic_settings import BaseSettings
from pathlib import Path
import os

class Settings(BaseSettings):
    APP_NAME: str = "CyberNest"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite:///./cybernest.db"
    SECRET_KEY: str = "cybernest-dev-secret-CHANGE-IN-PRODUCTION-use-256bit-random"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    REDIS_URL: str = "redis://localhost:6379/0"
    LOG_RETENTION_DAYS: int = 90
    MAX_EVENTS_PER_QUERY: int = 10000
    RULES_DIR: Path = Path(__file__).resolve().parent.parent.parent / "config" / "rules"
    PLAYBOOKS_DIR: Path = Path(__file__).resolve().parent.parent.parent / "config" / "playbooks"
    MAX_CONCURRENT_PLAYBOOKS: int = 10
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    OTX_API_KEY: str = ""
    SLACK_WEBHOOK_URL: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "cybernest@yourdomain.com"
    PAGERDUTY_INTEGRATION_KEY: str = ""
    FIREWALL_TYPE: str = "iptables"
    AWS_NACL_ID: str = ""
    AWS_REGION: str = "us-east-1"
    SYSLOG_UDP_PORT: int = 5514
    SYSLOG_TCP_PORT: int = 6601

    model_config = {"env_file": ".env", "env_prefix": "CYBERNEST_"}

settings = Settings()
''')

# ─────────────────────────────────────────────────────────────
# backend/core/database.py
# ─────────────────────────────────────────────────────────────
write("backend/core/database.py", '''"""Database setup."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from core.config import settings

SYNC_DB_URL = (
    settings.DATABASE_URL
    .replace("sqlite+aiosqlite", "sqlite")
    .replace("sqlite+pysqlite", "sqlite")
)
engine = create_engine(
    SYNC_DB_URL, echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in SYNC_DB_URL else {},
)
SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

async def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
''')

# ─────────────────────────────────────────────────────────────
# backend/core/models.py
# ─────────────────────────────────────────────────────────────
write("backend/core/models.py", r'''"""CyberNest Multi-Tenant Data Models."""
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
''')

# ─────────────────────────────────────────────────────────────
# backend/core/auth.py
# ─────────────────────────────────────────────────────────────
write("backend/core/auth.py", '''"""Authentication + tenant-scoped session."""
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
import bcrypt
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from loguru import logger
from core.config import settings
from core.database import get_db
from core.models import User, Tenant, UserRole, AuditLog

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def get_tenant_by_ingest_token(token: str, db: Session) -> Optional[Tenant]:
    return db.execute(
        select(Tenant).where(Tenant.ingest_token == token, Tenant.is_active == True)
    ).scalar_one_or_none()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalid or expired")
    username = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    q = select(User).where(User.username == username)
    if tenant_id:
        q = q.where(User.tenant_id == tenant_id)
    user = db.execute(q).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def get_current_tenant(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Tenant:
    if current_user.role == UserRole.SUPER_ADMIN:
        return None
    if not current_user.tenant_id:
        raise HTTPException(status_code=403, detail="User has no tenant assigned")
    tenant = db.execute(
        select(Tenant).where(Tenant.id == current_user.tenant_id, Tenant.is_active == True)
    ).scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=403, detail="Tenant not found or suspended")
    return tenant

def require_role(*roles: UserRole):
    def checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {[r.value for r in roles]}")
        return current_user
    return checker

def audit(db, action, user, resource=None, resource_id=None, details=None, request=None):
    db.add(AuditLog(
        tenant_id=user.tenant_id, user_id=user.id, username=user.username,
        action=action, resource=resource, resource_id=resource_id,
        details=details or {},
        ip_address=request.client.host if request else None,
    ))
''')

# ─────────────────────────────────────────────────────────────
# backend/siem/detection.py
# ─────────────────────────────────────────────────────────────
write("backend/siem/detection.py", r'''"""Detection engine — rules cached at startup, not reloaded per event."""
import yaml, re, threading
from pathlib import Path
from typing import Optional
from loguru import logger
from core.config import settings

_rules_cache: list[dict] = []
_rules_lock = threading.Lock()
_rules_loaded = False

def load_rules() -> list[dict]:
    global _rules_cache, _rules_loaded
    rules = []
    rules_dir = settings.RULES_DIR
    if not rules_dir.exists():
        logger.error(f"Rules directory not found: {rules_dir}")
        return rules
    for rule_file in sorted(rules_dir.glob("*.yml")):
        try:
            with open(rule_file) as f:
                for doc in yaml.safe_load_all(f):
                    if doc and isinstance(doc, dict):
                        doc["_source_file"] = rule_file.name
                        rules.append(doc)
        except Exception as e:
            logger.error(f"Failed to load rule {rule_file}: {e}")
    logger.info(f"Detection engine: loaded {len(rules)} rules from {rules_dir}")
    with _rules_lock:
        _rules_cache = rules
        _rules_loaded = True
    return rules

def get_rules() -> list[dict]:
    global _rules_loaded
    if not _rules_loaded:
        load_rules()
    return _rules_cache

def reload_rules() -> int:
    global _rules_loaded
    _rules_loaded = False
    return len(load_rules())

def evaluate_condition(event: dict, condition: dict) -> bool:
    field = condition.get("field")
    operator = condition.get("operator", "equals")
    value = condition.get("value")
    if not field or value is None:
        return False
    event_value = event.get(field)
    if event_value is None:
        return False
    ev = str(event_value).lower()
    vv = str(value).lower()
    if operator == "equals":       return ev == vv
    if operator == "contains":     return vv in ev
    if operator == "not_contains": return vv not in ev
    if operator == "startswith":   return ev.startswith(vv)
    if operator == "endswith":     return ev.endswith(vv)
    if operator == "regex":
        try: return bool(re.search(vv, ev, re.IGNORECASE))
        except: return False
    if operator == "gt":
        try: return float(ev) > float(vv)
        except: return False
    if operator == "lt":
        try: return float(ev) < float(vv)
        except: return False
    if operator == "in":
        vals = value if isinstance(value, list) else [value]
        return ev in [str(v).lower() for v in vals]
    return False

def evaluate_rule(event: dict, rule: dict) -> Optional[dict]:
    if not rule.get("enabled", True):
        return None
    conditions = rule.get("conditions", [])
    logic = rule.get("logic", "and").lower()
    if not conditions:
        return None
    results = [evaluate_condition(event, c) for c in conditions]
    if not (all(results) if logic == "and" else any(results)):
        return None
    return {
        "rule_name": rule.get("name", "Unknown"),
        "severity":  rule.get("severity", "medium"),
        "title":     rule.get("alert_title", f"Detection: {rule.get('name')}"),
        "description": rule.get("description", ""),
        "mitre_tactic":    rule.get("mitre_tactic"),
        "mitre_technique": rule.get("mitre_technique"),
        "source_file":     rule.get("_source_file", ""),
    }

def run_detection(event_data: dict) -> list[dict]:
    alerts = []
    for rule in get_rules():
        result = evaluate_rule(event_data, rule)
        if result:
            result["source_event"] = event_data
            alerts.append(result)
            logger.info(f"[DETECTION] {result[\'rule_name\']} | {result[\'severity\']} | src={event_data.get(\'src_ip\',\'N/A\')}")
    return alerts
''')

# ─────────────────────────────────────────────────────────────
# backend/siem/ingest.py
# ─────────────────────────────────────────────────────────────
write("backend/siem/ingest.py", '''"""Log ingestion — tenant-scoped parse, store, detect, broadcast."""
import asyncio
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select
from loguru import logger
from core.models import Event, Alert, AlertStatus, Severity, LogSource
from siem.parser import parse_log
from siem.detection import run_detection
from api.ws import broadcast_alert

SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}

def ingest_log(db: Session, raw_log: str, tenant_id: int, source_id: int = None) -> dict:
    parsed = parse_log(raw_log)
    event = Event(
        tenant_id=tenant_id, timestamp=datetime.now(timezone.utc),
        source_id=source_id, raw_log=raw_log, parsed=parsed,
        severity=SEVERITY_MAP.get(parsed.get("severity_raw", "info"), Severity.INFO),
        category=parsed.get("category"), src_ip=parsed.get("src_ip"),
        dst_ip=parsed.get("dst_ip"), hostname=parsed.get("hostname"),
        message=parsed.get("message"), mitre_tactic=parsed.get("mitre_tactic"),
        mitre_technique=parsed.get("mitre_technique"),
    )
    db.add(event)
    db.flush()
    if source_id:
        src = db.execute(
            select(LogSource).where(LogSource.id == source_id, LogSource.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if src:
            src.last_seen = datetime.now(timezone.utc)
    event_data = {
        "id": event.id, "tenant_id": tenant_id, "raw_log": raw_log,
        "src_ip": parsed.get("src_ip"), "dst_ip": parsed.get("dst_ip"),
        "hostname": parsed.get("hostname"), "message": parsed.get("message"),
        "category": parsed.get("category"),
        "severity": event.severity.value if event.severity else "info",
        "user": parsed.get("user"),
    }
    triggered = run_detection(event_data)
    created_alerts = []
    for ad in triggered:
        alert = Alert(
            tenant_id=tenant_id,
            severity=SEVERITY_MAP.get(ad["severity"], Severity.MEDIUM),
            status=AlertStatus.NEW, title=ad["title"], description=ad["description"],
            source_event_ids=[event.id],
            ioc_data={
                "src_ip": parsed.get("src_ip"), "dst_ip": parsed.get("dst_ip"),
                "hostname": parsed.get("hostname"), "user": parsed.get("user"),
                "rule_name": ad["rule_name"],
                "mitre_tactic": ad.get("mitre_tactic"),
                "mitre_technique": ad.get("mitre_technique"),
            },
        )
        db.add(alert)
        db.flush()
        payload = {**ad, "id": alert.id, "tenant_id": tenant_id,
                   "created_at": datetime.now(timezone.utc).isoformat()}
        created_alerts.append(payload)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(broadcast_alert(payload, tenant_id))
        except RuntimeError:
            pass
    db.commit()
    return {"event_id": event.id, "alerts_triggered": len(created_alerts),
            "alerts": created_alerts, "source_ip": parsed.get("src_ip")}

def ingest_batch(db, logs, tenant_id, source_id=None):
    total, results = 0, []
    for raw in logs:
        r = ingest_log(db, raw, tenant_id, source_id)
        results.append(r)
        total += r["alerts_triggered"]
    return {"events_ingested": len(results), "alerts_triggered": total}
''')

# ─────────────────────────────────────────────────────────────
# backend/api/ws.py
# ─────────────────────────────────────────────────────────────
write("backend/api/ws.py", '''"""WebSocket — per-tenant live alert streaming."""
import asyncio, json
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from loguru import logger

router = APIRouter()

class TenantConnectionManager:
    def __init__(self):
        self._pools: dict[int, list[WebSocket]] = {}

    async def connect(self, ws: WebSocket, tenant_id: int):
        await ws.accept()
        self._pools.setdefault(tenant_id, []).append(ws)

    def disconnect(self, ws: WebSocket, tenant_id: int):
        pool = self._pools.get(tenant_id, [])
        if ws in pool:
            pool.remove(ws)

    async def broadcast(self, data: dict, tenant_id: int):
        pool = self._pools.get(tenant_id, [])
        if not pool: return
        message = json.dumps(data, default=str)
        dead = []
        for ws in pool:
            try: await ws.send_text(message)
            except: dead.append(ws)
        for ws in dead: self.disconnect(ws, tenant_id)

    async def send(self, ws: WebSocket, data: dict):
        try: await ws.send_text(json.dumps(data, default=str))
        except: pass

manager = TenantConnectionManager()

@router.websocket("/alerts/live")
async def websocket_alerts(websocket: WebSocket, tenant_id: int = Query(...)):
    await manager.connect(websocket, tenant_id)
    await manager.send(websocket, {"type": "connected", "tenant_id": tenant_id,
                                    "timestamp": datetime.now(timezone.utc).isoformat()})
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await manager.send(websocket, {"type": "pong"})
            except asyncio.TimeoutError:
                await manager.send(websocket, {"type": "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat()})
            except: pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, tenant_id)

async def broadcast_alert(alert_data: dict, tenant_id: int):
    await manager.broadcast({"type": "new_alert", "alert": alert_data,
                               "timestamp": datetime.now(timezone.utc).isoformat()}, tenant_id)
''')

# ─────────────────────────────────────────────────────────────
# backend/integrations/__init__.py
# ─────────────────────────────────────────────────────────────
write("backend/integrations/__init__.py", "")

# ─────────────────────────────────────────────────────────────
# backend/integrations/threat_intel.py
# ─────────────────────────────────────────────────────────────
write("backend/integrations/threat_intel.py", '''"""Real threat intel: VirusTotal + AbuseIPDB."""
import asyncio, httpx, time
from loguru import logger
from core.config import settings

_cache: dict = {}
CACHE_TTL = 3600

def _get(key):
    e = _cache.get(key)
    return e["data"] if e and time.time() - e["ts"] < CACHE_TTL else None

def _set(key, data):
    _cache[key] = {"data": data, "ts": time.time()}

async def lookup_virustotal(ioc: str, ioc_type: str = "ip") -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"source": "virustotal", "status": "no_api_key", "ioc": ioc}
    key = f"vt:{ioc_type}:{ioc}"
    if c := _get(key): return c
    urls = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
            "hash": f"https://www.virustotal.com/api/v3/files/{ioc}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(urls.get(ioc_type, urls["ip"]),
                                  headers={"x-apikey": settings.VIRUSTOTAL_API_KEY})
            if r.status_code == 200:
                stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                result = {"source": "virustotal", "ioc": ioc,
                          "malicious": stats.get("malicious", 0),
                          "suspicious": stats.get("suspicious", 0),
                          "harmless": stats.get("harmless", 0),
                          "verdict": "malicious" if stats.get("malicious",0)>2 else
                                     "suspicious" if stats.get("suspicious",0)>2 else "clean",
                          "status": "ok"}
                _set(key, result); return result
            return {"source": "virustotal", "ioc": ioc, "status": f"http_{r.status_code}"}
    except Exception as e:
        return {"source": "virustotal", "ioc": ioc, "status": "error", "error": str(e)}

async def lookup_abuseipdb(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {"source": "abuseipdb", "status": "no_api_key", "ip": ip}
    key = f"abuse:{ip}"
    if c := _get(key): return c
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90})
            if r.status_code == 200:
                d = r.json().get("data", {})
                result = {"source": "abuseipdb", "ip": ip,
                          "abuse_score": d.get("abuseConfidenceScore", 0),
                          "country": d.get("countryCode", ""),
                          "isp": d.get("isp", ""),
                          "total_reports": d.get("totalReports", 0),
                          "is_tor": d.get("isTor", False),
                          "verdict": "malicious" if d.get("abuseConfidenceScore",0)>75 else
                                     "suspicious" if d.get("abuseConfidenceScore",0)>25 else "clean",
                          "status": "ok"}
                _set(key, result); return result
            return {"source": "abuseipdb", "ip": ip, "status": f"http_{r.status_code}"}
    except Exception as e:
        return {"source": "abuseipdb", "ip": ip, "status": "error", "error": str(e)}

async def enrich_ioc(ioc: str, ioc_type: str = "ip") -> dict:
    tasks = [lookup_virustotal(ioc, ioc_type)]
    if ioc_type == "ip":
        tasks.append(lookup_abuseipdb(ioc))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    enriched = {"ioc": ioc, "type": ioc_type, "sources": [], "verdict": "unknown"}
    for r in results:
        if isinstance(r, Exception): continue
        enriched["sources"].append(r)
        v = r.get("verdict", "unknown")
        if v == "malicious": enriched["verdict"] = "malicious"
        elif v == "suspicious" and enriched["verdict"] != "malicious": enriched["verdict"] = "suspicious"
        elif v == "clean" and enriched["verdict"] == "unknown": enriched["verdict"] = "clean"
    return enriched
''')

# ─────────────────────────────────────────────────────────────
# backend/integrations/notifications.py
# ─────────────────────────────────────────────────────────────
write("backend/integrations/notifications.py", '''"""Real notifications: Slack, Email, PagerDuty."""
import httpx, smtplib, asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger
from core.config import settings

async def send_slack(message: str, channel: str = "#soc-alerts", severity: str = "medium") -> dict:
    if not settings.SLACK_WEBHOOK_URL:
        return {"status": "no_webhook_configured"}
    colors = {"critical":"#dc2626","high":"#ea580c","medium":"#ca8a04","low":"#2563eb","info":"#6b7280"}
    payload = {"attachments": [{"color": colors.get(severity.lower(),"#6b7280"),
        "title": f"CyberNest Alert — {severity.upper()}", "text": message,
        "footer": "CyberNest SIEM", "ts": int(__import__("time").time())}]}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(settings.SLACK_WEBHOOK_URL, json=payload)
            return {"status": "sent"} if r.status_code == 200 else {"status": f"error_{r.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def send_email(subject: str, body: str, to: str = None) -> dict:
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        return {"status": "smtp_not_configured"}
    recipient = to or settings.SMTP_USER
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[CyberNest Alert] {subject}"
        msg["From"] = settings.SMTP_FROM
        msg["To"] = recipient
        msg.attach(MIMEText(body, "plain"))
        def _send():
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as s:
                s.starttls(); s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                s.sendmail(settings.SMTP_FROM, recipient, msg.as_string())
        await asyncio.get_event_loop().run_in_executor(None, _send)
        return {"status": "sent", "to": recipient}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def send_pagerduty(title: str, details: str, severity: str = "error") -> dict:
    if not settings.PAGERDUTY_INTEGRATION_KEY:
        return {"status": "no_pd_key_configured"}
    sev_map = {"critical":"critical","high":"error","medium":"warning","low":"info"}
    payload = {"routing_key": settings.PAGERDUTY_INTEGRATION_KEY, "event_action": "trigger",
               "payload": {"summary": title, "severity": sev_map.get(severity.lower(),"error"),
                           "source": "CyberNest SIEM", "custom_details": {"details": details}}}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post("https://events.pagerduty.com/v2/enqueue", json=payload)
            return {"status": "triggered"} if r.status_code in (200,202) else {"status": f"error_{r.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def notify(channel: str, message: str, severity: str = "medium", subject: str = None) -> dict:
    ch = channel.lower()
    if ch in ("slack","soc-alerts","#soc-alerts"): return await send_slack(message, severity=severity)
    if ch == "email": return await send_email(subject or message[:80], message)
    if ch == "pagerduty": return await send_pagerduty(subject or message[:80], message, severity)
    if settings.SLACK_WEBHOOK_URL: return await send_slack(message, channel, severity)
    logger.info(f"[NOTIFY] [{channel}] {message}")
    return {"status": "logged_only"}
''')

# ─────────────────────────────────────────────────────────────
# backend/integrations/firewall.py
# ─────────────────────────────────────────────────────────────
write("backend/integrations/firewall.py", '''"""Firewall integration: iptables, AWS NACL."""
import asyncio, subprocess
from loguru import logger
from core.config import settings

async def block_ip_iptables(ip: str, duration: int = 86400) -> dict:
    try:
        def _run():
            r1 = subprocess.run(["iptables","-I","INPUT","1","-s",ip,"-j","DROP",
                "-m","comment","--comment",f"CyberNest-{ip}"], capture_output=True, text=True)
            r2 = subprocess.run(["iptables","-I","OUTPUT","1","-d",ip,"-j","DROP",
                "-m","comment","--comment",f"CyberNest-{ip}"], capture_output=True, text=True)
            return r1, r2
        r1, r2 = await asyncio.get_event_loop().run_in_executor(None, _run)
        if r1.returncode == 0 and r2.returncode == 0:
            logger.warning(f"[FIREWALL] Blocked {ip} via iptables")
            return {"status": "blocked", "ip": ip, "method": "iptables"}
        return {"status": "error", "ip": ip, "error": r1.stderr or r2.stderr}
    except FileNotFoundError:
        return {"status": "error", "ip": ip, "error": "iptables not found — run as root"}
    except Exception as e:
        return {"status": "error", "ip": ip, "error": str(e)}

async def block_ip(ip: str, duration: int = 86400) -> dict:
    fw = settings.FIREWALL_TYPE.lower()
    if fw == "iptables": return await block_ip_iptables(ip, duration)
    logger.warning(f"[FIREWALL] SIMULATED block {ip} (FIREWALL_TYPE={fw})")
    return {"status": "simulated", "ip": ip, "note": f"Set CYBERNEST_FIREWALL_TYPE=iptables in .env"}
''')

# ─────────────────────────────────────────────────────────────
# backend/soar/case_manager.py
# ─────────────────────────────────────────────────────────────
write("backend/soar/case_manager.py", '''"""Case/Incident management — tenant-scoped."""
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from loguru import logger
from core.models import Incident, Alert, IncidentStatus, Severity

def create_incident(db, title, severity, tenant_id, description=None, assigned_to=None, alert_ids=None):
    incident = Incident(
        tenant_id=tenant_id, title=title, description=description,
        severity=Severity(severity), status=IncidentStatus.OPEN, assigned_to=assigned_to,
        timeline=[{"action":"created","timestamp":datetime.now(timezone.utc).isoformat(),"details":f"Incident created: {title}"}],
    )
    db.add(incident); db.flush()
    if alert_ids:
        alerts = db.execute(select(Alert).where(Alert.id.in_(alert_ids), Alert.tenant_id == tenant_id)).scalars().all()
        for a in alerts: a.incident_id = incident.id
    db.commit()
    logger.info(f"[INCIDENT] #{incident.id}: {title} (tenant={tenant_id})")
    return incident

def update_incident_status(db, incident_id, new_status, details=None):
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident: raise ValueError(f"Incident {incident_id} not found")
    old = incident.status
    incident.status = IncidentStatus(new_status)
    incident.timeline = (incident.timeline or []) + [{"action":"status_change",
        "timestamp":datetime.now(timezone.utc).isoformat(),"from":old.value,"to":new_status,
        "details":details or f"{old.value} → {new_status}"}]
    if new_status == "closed": incident.closed_at = datetime.now(timezone.utc)
    db.commit(); return incident

def add_timeline_entry(db, incident_id, action, details):
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident: raise ValueError(f"Incident {incident_id} not found")
    incident.timeline = (incident.timeline or []) + [{"action":action,
        "timestamp":datetime.now(timezone.utc).isoformat(),"details":details}]
    db.commit(); return incident
''')

# ─────────────────────────────────────────────────────────────
# backend/soar/playbook_engine.py
# ─────────────────────────────────────────────────────────────
write("backend/soar/playbook_engine.py", '''"""SOAR Playbook Engine — real actions, template resolution, conditional steps."""
import yaml, asyncio
from datetime import datetime, timezone
from loguru import logger
from core.config import settings
from integrations.threat_intel import enrich_ioc
from integrations.notifications import notify
from integrations.firewall import block_ip

def _resolve(value, context):
    if not isinstance(value, str): return value
    for k, v in context.items():
        value = value.replace(f"{{{{{k}}}}}", str(v) if v else "")
    return value

def _resolve_params(params, context):
    return {k: _resolve(v, context) if isinstance(v, str) else
               _resolve_params(v, context) if isinstance(v, dict) else v
            for k, v in params.items()}

async def action_log(params, context):
    msg = _resolve(params.get("message","Playbook step executed"), context)
    logger.info(f"[PLAYBOOK] LOG: {msg}")
    return {"status": "logged", "message": msg}

async def action_block_ip(params, context):
    ip = _resolve(params.get("ip",""), context) or context.get("src_ip")
    if not ip: return {"status": "skipped", "reason": "No IP in context"}
    return await block_ip(ip, int(params.get("duration", 86400)))

async def action_isolate_host(params, context):
    hostname = _resolve(params.get("hostname",""), context) or context.get("hostname")
    if not hostname: return {"status": "skipped", "reason": "No hostname in context"}
    logger.warning(f"[PLAYBOOK] ISOLATE HOST: {hostname} — configure EDR API")
    return {"status": "isolation_requested", "hostname": hostname, "note": "Configure EDR integration"}

async def action_disable_user(params, context):
    username = _resolve(params.get("username",""), context) or context.get("user")
    if not username: return {"status": "skipped", "reason": "No username in context"}
    logger.warning(f"[PLAYBOOK] DISABLE USER: {username} — configure AD/Okta")
    return {"status": "disable_requested", "username": username}

async def action_enrich_ioc(params, context):
    ioc = _resolve(params.get("ioc",""), context) or context.get("src_ip")
    ioc_type = params.get("type", "ip")
    if not ioc: return {"status": "skipped", "reason": "No IOC value"}
    result = await enrich_ioc(ioc, ioc_type)
    context["ioc_verdict"] = result.get("verdict","unknown")
    context["enrichment"] = result
    return result

async def action_send_notification(params, context):
    p = _resolve_params(params, context)
    return await notify(p.get("channel","slack"), p.get("message","CyberNest Alert"),
                        p.get("severity") or context.get("severity","medium"),
                        p.get("subject"))

async def action_create_ticket(params, context):
    p = _resolve_params(params, context)
    title = p.get("title","CyberNest Incident")
    logger.info(f"[PLAYBOOK] CREATE TICKET: {title}")
    return {"status": "created", "title": title, "note": "Configure Jira/TheHive in integrations/"}

async def action_virustotal_lookup(params, context):
    from integrations.threat_intel import lookup_virustotal
    ioc = _resolve(params.get("target",""), context) or context.get("src_ip")
    result = await lookup_virustotal(ioc, params.get("type","ip"))
    context["vt_result"] = result; return result

async def action_abuseipdb_check(params, context):
    from integrations.threat_intel import lookup_abuseipdb
    ip = _resolve(params.get("ip",""), context) or context.get("src_ip")
    result = await lookup_abuseipdb(ip)
    context["abuse_result"] = result; return result

ACTIONS = {
    "log": action_log, "block_ip": action_block_ip, "firewall_block_ip": action_block_ip,
    "isolate_host": action_isolate_host, "disable_user": action_disable_user,
    "enrich_ioc": action_enrich_ioc, "send_notification": action_send_notification,
    "notify": action_send_notification, "create_ticket": action_create_ticket,
    "virustotal_lookup": action_virustotal_lookup, "abuseipdb_check": action_abuseipdb_check,
}

def _check_condition(condition, context):
    if not condition: return True
    try:
        cond = _resolve(condition, context)
        return bool(eval(cond, {"__builtins__": {}}, {k:v for k,v in context.items() if not callable(v)}))
    except Exception as e:
        logger.warning(f"Condition eval failed: {e}"); return True

async def execute_playbook(playbook: dict, context: dict) -> dict:
    results = []
    name = playbook.get("name","Unknown")
    steps = playbook.get("steps",[])
    logger.info(f"[PLAYBOOK] Starting: {name} ({len(steps)} steps)")
    for i, step in enumerate(steps):
        step_name = step.get("name", f"Step {i+1}")
        action_type = step.get("action")
        params = step.get("params", step.get("input", {}))
        condition = step.get("condition")
        if condition and not _check_condition(condition, context):
            results.append({"step":step_name,"status":"skipped","reason":f"Condition not met: {condition}"})
            continue
        handler = ACTIONS.get(action_type)
        if not handler:
            results.append({"step":step_name,"status":"error","reason":f"Unknown action: {action_type}"})
            continue
        try:
            result = await asyncio.wait_for(handler(params, context), timeout=step.get("timeout",60))
            result["step"] = step_name
            output_key = step.get("output")
            if output_key: context[output_key] = result
        except asyncio.TimeoutError:
            result = {"step":step_name,"status":"timeout","reason":f"Exceeded {step.get(\'timeout\',60)}s"}
        except Exception as e:
            result = {"step":step_name,"status":"error","reason":str(e)}
            logger.error(f"[PLAYBOOK] Step \'{step_name}\' failed: {e}")
        if result.get("status") in ("error","timeout") and step.get("on_failure") == "abort":
            results.append(result)
            return {"playbook":name,"status":"aborted","steps_completed":i,"results":results}
        results.append(result)
    return {"playbook":name,"status":"completed","steps_completed":len(steps),"results":results}
''')

# ─────────────────────────────────────────────────────────────
# backend/siem/syslog_listener.py
# ─────────────────────────────────────────────────────────────
write("backend/siem/syslog_listener.py", '''"""
Real syslog listener — UDP + TCP.
Receives logs from Linux servers, firewalls, network devices.
Enable: set CYBERNEST_SYSLOG_ENABLED=true in .env
"""
import asyncio, threading
from loguru import logger
from core.database import SessionLocal
from siem.ingest import ingest_log
from core.config import settings

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"[SYSLOG] UDP ready on :{settings.SYSLOG_UDP_PORT}")
    def datagram_received(self, data, addr):
        raw = data.decode("utf-8", errors="replace").strip()
        if not raw: return
        threading.Thread(target=self._process, args=(raw, addr[0]), daemon=True).start()
    def _process(self, raw, src_ip):
        if src_ip not in raw: raw = f"{raw} [from:{src_ip}]"
        db = SessionLocal()
        try: ingest_log(db, raw, self.tenant_id)
        except Exception as e: logger.error(f"[SYSLOG UDP] {e}")
        finally: db.close()

class SyslogTCPServer:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
    async def handle(self, reader, writer):
        src_ip = writer.get_extra_info("peername", ("unknown",))[0]
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=300)
                if not line: break
                raw = line.decode("utf-8", errors="replace").strip()
                if not raw: continue
                if src_ip not in raw: raw = f"{raw} [from:{src_ip}]"
                db = SessionLocal()
                try: ingest_log(db, raw, self.tenant_id)
                except Exception as e: logger.error(f"[SYSLOG TCP] {e}")
                finally: db.close()
        except (asyncio.TimeoutError, Exception):
            pass
        finally:
            writer.close()

async def start_syslog_listeners(tenant_id: int = None):
    loop = asyncio.get_event_loop()
    try:
        await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(tenant_id),
            local_addr=("0.0.0.0", settings.SYSLOG_UDP_PORT))
        logger.info(f"[SYSLOG] UDP on 0.0.0.0:{settings.SYSLOG_UDP_PORT}")
    except Exception as e:
        logger.error(f"[SYSLOG] UDP bind failed: {e}")
    try:
        tcp = SyslogTCPServer(tenant_id)
        server = await asyncio.start_server(tcp.handle, "0.0.0.0", settings.SYSLOG_TCP_PORT)
        logger.info(f"[SYSLOG] TCP on 0.0.0.0:{settings.SYSLOG_TCP_PORT}")
        async with server: await server.serve_forever()
    except Exception as e:
        logger.error(f"[SYSLOG] TCP bind failed: {e}")
''')

# ─────────────────────────────────────────────────────────────
# backend/main.py
# ─────────────────────────────────────────────────────────────
write("backend/main.py", '''"""CyberNest SIEM+SOAR — Multi-Tenant Entry Point"""
import asyncio, os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from loguru import logger
from core.database import init_db
from core.config import settings
from api.routes import router as api_router
from api.ws import router as ws_router
from siem.detection import load_rules

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 55)
    logger.info("  CyberNest SIEM+SOAR v1.0 — Multi-Tenant")
    logger.info("=" * 55)
    await init_db()
    rules = load_rules()
    logger.info(f"[DB] Ready | [DETECTION] {len(rules)} rules loaded")
    logger.info(f"[VT]  VirusTotal:  {\'configured\' if settings.VIRUSTOTAL_API_KEY else \'set CYBERNEST_VIRUSTOTAL_API_KEY\'}")
    logger.info(f"[AI]  AbuseIPDB:   {\'configured\' if settings.ABUSEIPDB_API_KEY else \'set CYBERNEST_ABUSEIPDB_API_KEY\'}")
    logger.info(f"[SL]  Slack:       {\'configured\' if settings.SLACK_WEBHOOK_URL else \'set CYBERNEST_SLACK_WEBHOOK_URL\'}")
    logger.info(f"[FW]  Firewall:    {settings.FIREWALL_TYPE}")
    if os.getenv("CYBERNEST_SYSLOG_ENABLED","false").lower() == "true":
        from siem.syslog_listener import start_syslog_listeners
        asyncio.create_task(start_syslog_listeners())
        logger.info(f"[SYSLOG] UDP:{settings.SYSLOG_UDP_PORT} TCP:{settings.SYSLOG_TCP_PORT}")
    logger.info("[READY] http://localhost:8000  |  docs: /api/docs")
    yield
    logger.info("[SHUTDOWN] CyberNest shutting down")

app = FastAPI(title="CyberNest SIEM+SOAR", version="1.0.0", lifespan=lifespan,
              docs_url="/api/docs", redoc_url="/api/redoc")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router, prefix="/ws")

frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
''')

# ─────────────────────────────────────────────────────────────
# .gitignore
# ─────────────────────────────────────────────────────────────
write(".gitignore", '''# Environment — NEVER commit these
.env
*.env

# Databases
*.db
*.sqlite
*.sqlite3

# Python
__pycache__/
*.py[cod]
*.pyo
.pytest_cache/
*.egg-info/
dist/
build/
.venv/
venv/
env/

# Node
node_modules/
dist/

# IDE
.vscode/settings.json
.idea/
*.swp

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Docker
*.pid
''')

# ─────────────────────────────────────────────────────────────
# .env.example
# ─────────────────────────────────────────────────────────────
write(".env.example", '''# CyberNest — copy to .env and fill in your values

# Core
CYBERNEST_DEBUG=false
CYBERNEST_SECRET_KEY=CHANGE-ME-use-python-secrets-token-hex-32

# Database (SQLite for dev, PostgreSQL for prod)
CYBERNEST_DATABASE_URL=sqlite:///./cybernest.db
# CYBERNEST_DATABASE_URL=postgresql://cybernest:password@localhost:5432/cybernest

# Syslog listener
CYBERNEST_SYSLOG_ENABLED=false
CYBERNEST_SYSLOG_UDP_PORT=5514
CYBERNEST_SYSLOG_TCP_PORT=6601

# Threat Intel
CYBERNEST_VIRUSTOTAL_API_KEY=
CYBERNEST_ABUSEIPDB_API_KEY=

# Notifications
CYBERNEST_SLACK_WEBHOOK_URL=
CYBERNEST_SMTP_HOST=smtp.gmail.com
CYBERNEST_SMTP_PORT=587
CYBERNEST_SMTP_USER=
CYBERNEST_SMTP_PASSWORD=
CYBERNEST_SMTP_FROM=cybernest@yourdomain.com
CYBERNEST_PAGERDUTY_INTEGRATION_KEY=

# Firewall
CYBERNEST_FIREWALL_TYPE=iptables
''')

print("\n✅ All files written successfully.\n")
print("Next steps:")
print("  1. cd CyberNest")
print("  2. pip install -r backend/requirements.txt")
print("  3. cd backend && python seed_multitenant.py")
print("  4. git add -A")
print('  5. git commit -m "feat: multi-tenant SIEM+SOAR — real integrations, data isolation, audit log"')
print("  6. git push origin master")

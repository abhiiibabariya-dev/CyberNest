"""API routes — auth-enforced, tenant-scoped."""

from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, func, desc, and_
from sqlalchemy.orm import Session

from core.database import get_db
from core.models import (
    Event, Alert, AlertStatus, DetectionRule, LogSource,
    Incident, IncidentStatus, Playbook, PlaybookRun, PlaybookStatus,
    User, UserRole, Tenant, Severity, AuditLog,
)
from core.schemas import (
    UserCreate, UserResponse, LoginRequest, LoginResponse, AuthTokens, RefreshRequest,
    EventCreate, EventResponse, SearchRequest, SearchResult,
    AlertResponse, AlertUpdate, AlertComment, AlertCommentCreate, AlertStats,
    LogSourceCreate, LogSourceResponse,
    RuleCreate, RuleUpdate, RuleResponse, RuleStats,
    IncidentCreate, IncidentResponse, IncidentUpdate,
    PlaybookCreate, PlaybookResponse, PlaybookTrigger, PlaybookRunResponse,
    DashboardStats, ThreatLookupResult, IOCResponse,
)
from core.auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, get_current_tenant, require_role, audit,
)
from core.config import settings
from jose import jwt, JWTError
from siem.ingest import ingest_log, ingest_batch
from siem.detection import reload_rules, get_rules
from soar.case_manager import create_incident, update_incident_status, add_timeline_entry
from soar.playbook_engine import execute_playbook
from integrations.threat_intel import enrich_ioc

router = APIRouter()


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════

def _tenant_id(tenant: Optional[Tenant], user: User) -> Optional[int]:
    """Resolve effective tenant_id. Super-admin has no tenant scope."""
    if tenant:
        return tenant.id
    if user.role == UserRole.SUPER_ADMIN:
        return None
    return user.tenant_id


def _scope(query, model, tenant_id: Optional[int]):
    """Apply tenant filter unless super-admin (tenant_id None)."""
    if tenant_id is not None:
        query = query.where(model.tenant_id == tenant_id)
    return query


def _severity_enum(value: str) -> Severity:
    return Severity(value.lower())


def _create_refresh_token(data: dict) -> str:
    payload = data.copy()
    payload["type"] = "refresh"
    payload["exp"] = datetime.now(timezone.utc) + timedelta(days=7)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _user_to_response(user: User) -> dict:
    return {
        "id": str(user.id),
        "tenant_id": user.tenant_id,
        "username": user.username,
        "email": user.email,
        "full_name": getattr(user, "full_name", "") or user.username,
        "role": user.role.value if hasattr(user.role, "value") else user.role,
        "is_active": user.is_active,
        "mfa_enabled": False,
        "last_login": user.last_login,
        "created_at": user.created_at,
    }


def _alert_to_response(a: Alert) -> dict:
    ioc = a.ioc_data or {}
    return {
        "id": str(a.id),
        "tenant_id": a.tenant_id,
        "rule_id": str(a.rule_id) if a.rule_id else None,
        "rule_name": ioc.get("rule_name"),
        "severity": a.severity.value if a.severity else "medium",
        "status": a.status.value if a.status else "new",
        "title": a.title,
        "description": a.description,
        "source": "siem",
        "source_ip": ioc.get("src_ip"),
        "destination_ip": ioc.get("dst_ip"),
        "hostname": ioc.get("hostname"),
        "username": ioc.get("user"),
        "assigned_to": a.assigned_to,
        "incident_id": str(a.incident_id) if a.incident_id else None,
        "tags": [],
        "mitre_tactics": [ioc["mitre_tactic"]] if ioc.get("mitre_tactic") else [],
        "mitre_techniques": [ioc["mitre_technique"]] if ioc.get("mitre_technique") else [],
        "observables": [],
        "event_count": len(a.source_event_ids or []) or 1,
        "comment_count": 0,
        "created_at": a.created_at,
        "updated_at": a.updated_at,
    }


def _rule_to_response(r: DetectionRule) -> dict:
    return {
        "id": str(r.id),
        "name": r.name,
        "description": r.description,
        "severity": r.severity.value if r.severity else "medium",
        "enabled": r.enabled,
        "rule_type": "siem",
        "logic": r.logic or {},
        "mitre_tactics": [r.mitre_tactic] if r.mitre_tactic else [],
        "mitre_techniques": [r.mitre_technique] if r.mitre_technique else [],
        "tags": [],
        "total_hits": 0,
        "match_count_24h": 0,
        "last_match": None,
        "author": "system",
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }


def _incident_to_response(i: Incident) -> dict:
    return {
        "id": str(i.id),
        "tenant_id": i.tenant_id,
        "title": i.title,
        "description": i.description,
        "severity": i.severity.value if i.severity else "medium",
        "status": i.status.value if i.status else "open",
        "priority": i.severity.value if i.severity else "medium",
        "assigned_to": i.assigned_to,
        "assignee_name": i.assigned_to,
        "tags": i.tags or [],
        "timeline": i.timeline or [],
        "alert_count": len(i.alerts) if i.alerts else 0,
        "task_count": 0,
        "tasks_completed": 0,
        "observable_count": 0,
        "created_at": i.created_at,
        "updated_at": i.updated_at,
        "closed_at": i.closed_at,
    }


def _playbook_to_response(p: Playbook) -> dict:
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "trigger_type": p.trigger_type,
        "trigger_conditions": p.trigger_conditions or {},
        "steps": p.steps or [],
        "enabled": p.enabled,
        "status": "active" if p.enabled else "disabled",
        "total_runs": 0,
        "successful_runs": 0,
        "created_at": p.created_at,
        "updated_at": None,
    }


def _run_to_response(r: PlaybookRun) -> dict:
    duration_ms = None
    if r.completed_at and r.started_at:
        duration_ms = int((r.completed_at - r.started_at).total_seconds() * 1000)
    return {
        "id": str(r.id),
        "playbook_id": str(r.playbook_id),
        "playbook_name": r.playbook.name if r.playbook else None,
        "incident_id": str(r.incident_id) if r.incident_id else None,
        "status": r.status.value if r.status else "running",
        "steps_completed": len(r.step_results or []),
        "steps_total": len(r.step_results or []),
        "step_results": r.step_results or [],
        "error_message": r.error,
        "started_at": r.started_at,
        "completed_at": r.completed_at,
        "duration_ms": duration_ms,
    }


# ═══════════════════════════════════════════════════════════════════
#  Auth
# ═══════════════════════════════════════════════════════════════════

@router.post("/auth/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.execute(select(User).where(User.username == user.username)).scalar_one_or_none()
    if existing:
        raise HTTPException(400, "Username already exists")
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
        role=UserRole(user.role) if user.role in [r.value for r in UserRole] else UserRole.ANALYST,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return _user_to_response(db_user)


@router.post("/auth/login", response_model=LoginResponse)
def login(credentials: LoginRequest, request: Request, db: Session = Depends(get_db)):
    identifier = credentials.username or credentials.email
    if not identifier or not credentials.password:
        raise HTTPException(400, "Username/email and password required")

    user = db.execute(
        select(User).where(
            (User.username == identifier) | (User.email == identifier)
        )
    ).scalar_one_or_none()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "Account disabled")

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "tenant_id": user.tenant_id,
        "role": user.role.value,
    }
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": _create_refresh_token(token_data),
        "token_type": "bearer",
        "user": _user_to_response(user),
    }


@router.post("/auth/refresh", response_model=AuthTokens)
def refresh_token(body: RefreshRequest, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(body.refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid refresh token")
    except JWTError:
        raise HTTPException(401, "Refresh token invalid or expired")

    username = payload.get("sub")
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(401, "User not found")

    token_data = {"sub": user.username, "user_id": user.id, "tenant_id": user.tenant_id, "role": user.role.value}
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": _create_refresh_token(token_data),
        "token_type": "bearer",
        "expires_in": 3600,
    }


@router.post("/auth/logout")
def logout(current_user: User = Depends(get_current_user)):
    return {"status": "ok"}


@router.get("/auth/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return _user_to_response(current_user)


# ═══════════════════════════════════════════════════════════════════
#  Dashboard
# ═══════════════════════════════════════════════════════════════════

@router.get("/dashboard/stats", response_model=DashboardStats)
def dashboard_stats(
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    def scoped_count(model, *extra):
        q = select(func.count(model.id))
        if tid is not None:
            q = q.where(model.tenant_id == tid)
        for ex in extra:
            q = q.where(ex)
        return db.execute(q).scalar() or 0

    total_events_24h = scoped_count(Event, Event.timestamp >= day_ago)
    total_alerts_24h = scoped_count(Alert, Alert.created_at >= day_ago)
    total_alerts = scoped_count(Alert)
    open_alerts = scoped_count(Alert, Alert.status == AlertStatus.NEW)
    critical_alerts = scoped_count(Alert, Alert.severity == Severity.CRITICAL)
    high_alerts = scoped_count(Alert, Alert.severity == Severity.HIGH)
    medium_alerts = scoped_count(Alert, Alert.severity == Severity.MEDIUM)
    low_alerts = scoped_count(Alert, Alert.severity == Severity.LOW)
    active_incidents = scoped_count(
        Incident, Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS])
    )
    total_rules = scoped_count(DetectionRule)
    active_rules = scoped_count(DetectionRule, DetectionRule.enabled == True)
    active_playbooks = scoped_count(Playbook, Playbook.enabled == True)
    resolved_today = scoped_count(
        Incident,
        Incident.status == IncidentStatus.CLOSED,
        Incident.closed_at >= now.replace(hour=0, minute=0, second=0, microsecond=0),
    )

    # EPS over last 60s
    recent_events = scoped_count(Event, Event.timestamp >= now - timedelta(seconds=60))
    eps = round(recent_events / 60.0, 2)

    # Alert trend 24h (hourly)
    alert_trend = []
    for i in range(24):
        hour_start = (now - timedelta(hours=23 - i)).replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        q = select(func.count(Alert.id)).where(
            Alert.created_at >= hour_start, Alert.created_at < hour_end
        )
        if tid is not None:
            q = q.where(Alert.tenant_id == tid)
        c = db.execute(q).scalar() or 0
        alert_trend.append({"hour": hour_start.strftime("%H:00"), "timestamp": hour_start.isoformat(), "count": c})

    # Top attackers
    q = select(Event.src_ip, func.count(Event.id).label("c")).where(Event.src_ip.isnot(None))
    if tid is not None:
        q = q.where(Event.tenant_id == tid)
    q = q.group_by(Event.src_ip).order_by(desc("c")).limit(10)
    top_attackers = [{"ip": r[0], "count": r[1]} for r in db.execute(q).all()]

    # Top rules (by alert count)
    q = select(DetectionRule.name, func.count(Alert.id).label("c")).join(
        Alert, Alert.rule_id == DetectionRule.id
    )
    if tid is not None:
        q = q.where(Alert.tenant_id == tid)
    q = q.group_by(DetectionRule.name).order_by(desc("c")).limit(10)
    top_rules = [{"rule": r[0], "count": r[1]} for r in db.execute(q).all()]

    # MITRE coverage
    q = select(DetectionRule.mitre_tactic, func.count(DetectionRule.id).label("c")).where(
        DetectionRule.mitre_tactic.isnot(None)
    )
    if tid is not None:
        q = q.where(DetectionRule.tenant_id == tid)
    q = q.group_by(DetectionRule.mitre_tactic)
    mitre_coverage = {r[0]: r[1] for r in db.execute(q).all()}

    # Alerts by severity (list format for dashboard)
    alerts_by_severity = [
        {"severity": "critical", "count": critical_alerts},
        {"severity": "high", "count": high_alerts},
        {"severity": "medium", "count": medium_alerts},
        {"severity": "low", "count": low_alerts},
    ]

    # Recent alerts
    q = select(Alert).order_by(desc(Alert.created_at)).limit(10)
    if tid is not None:
        q = q.where(Alert.tenant_id == tid)
    recent = [_alert_to_response(a) for a in db.execute(q).scalars().all()]

    return {
        "total_events_24h": total_events_24h,
        "total_alerts_24h": total_alerts_24h,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "active_incidents": active_incidents,
        "active_agents": 0,
        "total_agents": 0,
        "online_agents": 0,
        "offline_agents": 0,
        "total_rules": total_rules,
        "active_rules": active_rules,
        "active_playbooks": active_playbooks,
        "open_cases": active_incidents,
        "total_iocs": 0,
        "events_per_second": eps,
        "mttr_minutes": 0,
        "resolved_today": resolved_today,
        "alert_trend": alert_trend,
        "alerts_trend_24h": alert_trend,
        "alerts_by_severity": alerts_by_severity,
        "top_attackers": top_attackers,
        "top_rules": top_rules,
        "mitre_coverage": mitre_coverage,
        "recent_alerts": recent,
    }


# ═══════════════════════════════════════════════════════════════════
#  SIEM: Events
# ═══════════════════════════════════════════════════════════════════

@router.post("/events/ingest")
def ingest_event(
    event: EventCreate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant context required for ingestion")
    return ingest_log(db, event.raw_log, tenant.id, event.source_id)


@router.post("/events/ingest/batch")
def ingest_events_batch(
    logs: list[str],
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant context required")
    return ingest_batch(db, logs, tenant.id)


@router.post("/events/search", response_model=SearchResult)
def search_events(
    body: SearchRequest,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    started = datetime.now(timezone.utc)
    q = select(Event).order_by(desc(Event.timestamp))
    if tid is not None:
        q = q.where(Event.tenant_id == tid)
    if body.q:
        q = q.where(Event.raw_log.contains(body.q))
    if body.from_time:
        try:
            q = q.where(Event.timestamp >= datetime.fromisoformat(body.from_time.replace("Z", "+00:00")))
        except Exception:
            pass
    q = q.limit(body.size)
    rows = db.execute(q).scalars().all()
    hits = [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "severity": e.severity.value if e.severity else "info",
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "hostname": e.hostname,
            "message": e.message,
            "raw_log": e.raw_log,
            "category": e.category,
        }
        for e in rows
    ]
    took_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    return {"total": len(hits), "took_ms": took_ms, "hits": hits}


@router.get("/events", response_model=list[EventResponse])
def list_events(
    limit: int = Query(100, le=10000),
    offset: int = 0,
    severity: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Event).order_by(desc(Event.timestamp))
    if tid is not None:
        q = q.where(Event.tenant_id == tid)
    if severity:
        q = q.where(Event.severity == _severity_enum(severity))
    if src_ip:
        q = q.where(Event.src_ip == src_ip)
    if dst_ip:
        q = q.where(Event.dst_ip == dst_ip)
    if search:
        q = q.where(Event.raw_log.contains(search))
    q = q.offset(offset).limit(limit)
    return db.execute(q).scalars().all()


@router.get("/events/{event_id}", response_model=EventResponse)
def get_event(
    event_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Event).where(Event.id == event_id)
    if tid is not None:
        q = q.where(Event.tenant_id == tid)
    e = db.execute(q).scalar_one_or_none()
    if not e:
        raise HTTPException(404, "Event not found")
    return e


# ═══════════════════════════════════════════════════════════════════
#  SIEM: Alerts
# ═══════════════════════════════════════════════════════════════════

@router.get("/alerts")
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Alert).order_by(desc(Alert.created_at))
    if tid is not None:
        q = q.where(Alert.tenant_id == tid)
    if status:
        try:
            q = q.where(Alert.status == AlertStatus(status))
        except ValueError:
            pass
    if severity:
        q = q.where(Alert.severity == _severity_enum(severity))
    q = q.offset(offset).limit(limit)
    return [_alert_to_response(a) for a in db.execute(q).scalars().all()]


@router.get("/alerts/stats", response_model=AlertStats)
def alert_stats(
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)

    def count(cond=None):
        q = select(func.count(Alert.id))
        if tid is not None:
            q = q.where(Alert.tenant_id == tid)
        if cond is not None:
            q = q.where(cond)
        return db.execute(q).scalar() or 0

    by_severity = {sev.value: count(Alert.severity == sev) for sev in Severity}
    by_status = {st.value: count(Alert.status == st) for st in AlertStatus}

    now = datetime.now(timezone.utc)
    trend = []
    for i in range(24):
        hs = (now - timedelta(hours=23 - i)).replace(minute=0, second=0, microsecond=0)
        he = hs + timedelta(hours=1)
        trend.append({"timestamp": hs.isoformat(), "count": count(and_(Alert.created_at >= hs, Alert.created_at < he))})

    return {"total": count(), "by_severity": by_severity, "by_status": by_status, "trend": trend}


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Alert).where(Alert.id == alert_id)
    if tid is not None:
        q = q.where(Alert.tenant_id == tid)
    a = db.execute(q).scalar_one_or_none()
    if not a:
        raise HTTPException(404, "Alert not found")
    return _alert_to_response(a)


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    update: AlertUpdate,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Alert).where(Alert.id == alert_id)
    if tid is not None:
        q = q.where(Alert.tenant_id == tid)
    alert = db.execute(q).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    if update.status:
        try:
            alert.status = AlertStatus(update.status)
        except ValueError:
            raise HTTPException(400, f"Invalid status: {update.status}")
    if update.assigned_to is not None:
        alert.assigned_to = update.assigned_to
    db.commit()
    db.refresh(alert)
    return _alert_to_response(alert)


@router.get("/alerts/{alert_id}/comments")
def list_alert_comments(alert_id: int, current_user: User = Depends(get_current_user)):
    return []


@router.post("/alerts/{alert_id}/comments")
def add_alert_comment(
    alert_id: int,
    body: AlertCommentCreate,
    current_user: User = Depends(get_current_user),
):
    return {
        "id": f"c-{alert_id}-{int(datetime.now().timestamp())}",
        "alert_id": str(alert_id),
        "user_id": str(current_user.id),
        "user_name": current_user.username,
        "content": body.content,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/alerts/{alert_id}/create-case")
def create_case_from_alert(
    alert_id: int,
    body: dict,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    alert = db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant.id)).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    incident = create_incident(
        db,
        title=body.get("title", alert.title),
        severity=alert.severity.value,
        tenant_id=tenant.id,
        description=body.get("description", alert.description),
        assigned_to=current_user.username,
        alert_ids=[alert_id],
    )
    return _incident_to_response(incident)


# ═══════════════════════════════════════════════════════════════════
#  SIEM: Detection Rules
# ═══════════════════════════════════════════════════════════════════

@router.get("/rules")
def list_rules(
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(DetectionRule).order_by(DetectionRule.name)
    if tid is not None:
        q = q.where(DetectionRule.tenant_id == tid)
    return [_rule_to_response(r) for r in db.execute(q).scalars().all()]


@router.get("/rules/stats", response_model=RuleStats)
def rules_stats(
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    base = select(func.count(DetectionRule.id))
    if tid is not None:
        base = base.where(DetectionRule.tenant_id == tid)
    total = db.execute(base).scalar() or 0
    enabled = db.execute(
        base.where(DetectionRule.enabled == True) if tid is None else base.where(DetectionRule.enabled == True)
    ).scalar() or 0
    by_sev = {}
    for sev in Severity:
        q = select(func.count(DetectionRule.id)).where(DetectionRule.severity == sev)
        if tid is not None:
            q = q.where(DetectionRule.tenant_id == tid)
        by_sev[sev.value] = db.execute(q).scalar() or 0
    return {
        "total_rules": total,
        "enabled_rules": enabled,
        "disabled_rules": total - enabled,
        "matches_24h": 0,
        "top_firing_rules": [],
        "rules_by_severity": by_sev,
    }


@router.post("/rules")
def create_rule(
    rule: RuleCreate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    db_rule = DetectionRule(
        tenant_id=tenant.id,
        name=rule.name,
        description=rule.description,
        severity=_severity_enum(rule.severity),
        logic=rule.logic,
        enabled=rule.enabled,
        mitre_tactic=rule.mitre_tactic,
        mitre_technique=rule.mitre_technique,
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return _rule_to_response(db_rule)


@router.get("/rules/{rule_id}")
def get_rule(
    rule_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(DetectionRule).where(DetectionRule.id == rule_id)
    if tid is not None:
        q = q.where(DetectionRule.tenant_id == tid)
    r = db.execute(q).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    return _rule_to_response(r)


@router.put("/rules/{rule_id}")
def update_rule(
    rule_id: int,
    update: RuleUpdate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    r = db.execute(
        select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == tenant.id)
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    data = update.model_dump(exclude_unset=True)
    if "severity" in data:
        r.severity = _severity_enum(data.pop("severity"))
    for k, v in data.items():
        setattr(r, k, v)
    db.commit()
    db.refresh(r)
    return _rule_to_response(r)


@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    r = db.execute(
        select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == tenant.id)
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    db.delete(r)
    db.commit()
    return {"status": "deleted"}


@router.post("/rules/{rule_id}/toggle")
def toggle_rule(
    rule_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    r = db.execute(
        select(DetectionRule).where(DetectionRule.id == rule_id, DetectionRule.tenant_id == tenant.id)
    ).scalar_one_or_none()
    if not r:
        raise HTTPException(404, "Rule not found")
    r.enabled = not r.enabled
    db.commit()
    db.refresh(r)
    return _rule_to_response(r)


@router.post("/rules/reload")
def reload_detection_rules(current_user: User = Depends(require_role(UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN))):
    count = reload_rules()
    return {"status": "reloaded", "count": count}


# ═══════════════════════════════════════════════════════════════════
#  SIEM: Log Sources
# ═══════════════════════════════════════════════════════════════════

@router.get("/sources", response_model=list[LogSourceResponse])
def list_sources(
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(LogSource).order_by(LogSource.name)
    if tid is not None:
        q = q.where(LogSource.tenant_id == tid)
    return db.execute(q).scalars().all()


@router.post("/sources", response_model=LogSourceResponse)
def create_source(
    source: LogSourceCreate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    db_source = LogSource(tenant_id=tenant.id, **source.model_dump())
    db.add(db_source)
    db.commit()
    db.refresh(db_source)
    return db_source


# ═══════════════════════════════════════════════════════════════════
#  SOAR: Incidents / Cases
# ═══════════════════════════════════════════════════════════════════

@router.get("/incidents")
def list_incidents(
    status: Optional[str] = None,
    limit: int = Query(100, le=500),
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Incident).order_by(desc(Incident.created_at))
    if tid is not None:
        q = q.where(Incident.tenant_id == tid)
    if status:
        try:
            q = q.where(Incident.status == IncidentStatus(status))
        except ValueError:
            pass
    q = q.limit(limit)
    return [_incident_to_response(i) for i in db.execute(q).scalars().all()]


@router.post("/incidents")
def create_new_incident(
    data: IncidentCreate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    incident = create_incident(
        db,
        title=data.title,
        severity=data.severity,
        tenant_id=tenant.id,
        description=data.description,
        assigned_to=data.assigned_to,
        alert_ids=data.alert_ids,
    )
    return _incident_to_response(incident)


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Incident).where(Incident.id == incident_id)
    if tid is not None:
        q = q.where(Incident.tenant_id == tid)
    i = db.execute(q).scalar_one_or_none()
    if not i:
        raise HTTPException(404, "Incident not found")
    return _incident_to_response(i)


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    update: IncidentUpdate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    incident = db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant.id)
    ).scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")
    if update.status:
        update_incident_status(db, incident_id, update.status)
        incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one()
    if update.assigned_to is not None:
        incident.assigned_to = update.assigned_to
    if update.description is not None:
        incident.description = update.description
    if update.tags is not None:
        incident.tags = update.tags
    if update.severity:
        incident.severity = _severity_enum(update.severity)
    db.commit()
    return _incident_to_response(incident)


@router.post("/incidents/{incident_id}/timeline")
def add_incident_timeline_entry(
    incident_id: int,
    action: str = Query(...),
    details: str = Query(...),
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    incident = db.execute(
        select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant.id)
    ).scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")
    add_timeline_entry(db, incident_id, action, details)
    return {"status": "ok"}


# Cases is alias of Incidents for frontend compatibility
@router.get("/cases")
def list_cases(
    status: Optional[str] = None,
    limit: int = Query(100, le=500),
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return list_incidents(status, limit, current_user, tenant, db)


@router.post("/cases")
def create_case(
    data: IncidentCreate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return create_new_incident(data, current_user, tenant, db)


@router.get("/cases/{case_id}")
def get_case(
    case_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return get_incident(case_id, current_user, tenant, db)


@router.patch("/cases/{case_id}")
def update_case(
    case_id: int,
    update: IncidentUpdate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return update_incident(case_id, update, current_user, tenant, db)


@router.get("/cases/{case_id}/tasks")
def list_case_tasks(case_id: int, current_user: User = Depends(get_current_user)):
    return []


@router.post("/cases/{case_id}/tasks")
def create_case_task(case_id: int, body: dict, current_user: User = Depends(get_current_user)):
    return {
        "id": f"t-{case_id}-{int(datetime.now().timestamp())}",
        "case_id": str(case_id),
        "title": body.get("title", "New task"),
        "description": body.get("description", ""),
        "status": "pending",
        "order": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/cases/{case_id}/observables")
def list_case_observables(case_id: int, current_user: User = Depends(get_current_user)):
    return []


@router.post("/cases/{case_id}/observables")
def add_case_observable(case_id: int, body: dict, current_user: User = Depends(get_current_user)):
    return {
        "id": f"o-{case_id}-{int(datetime.now().timestamp())}",
        "case_id": str(case_id),
        "type": body.get("type", "ip"),
        "value": body.get("value", ""),
        "tlp": body.get("tlp", "amber"),
        "is_ioc": body.get("is_ioc", True),
        "tags": body.get("tags", []),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/cases/{case_id}/comments")
def list_case_comments(case_id: int, current_user: User = Depends(get_current_user)):
    return []


@router.post("/cases/{case_id}/comments")
def add_case_comment(case_id: int, body: dict, current_user: User = Depends(get_current_user)):
    return {
        "id": f"cc-{case_id}-{int(datetime.now().timestamp())}",
        "case_id": str(case_id),
        "user_id": str(current_user.id),
        "user_name": current_user.username,
        "content": body.get("content", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/cases/{case_id}/timeline")
def list_case_timeline(
    case_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Incident).where(Incident.id == case_id)
    if tid is not None:
        q = q.where(Incident.tenant_id == tid)
    i = db.execute(q).scalar_one_or_none()
    if not i:
        return []
    return [
        {
            "id": f"tl-{case_id}-{idx}",
            "case_id": str(case_id),
            "event_type": entry.get("action", "event"),
            "description": entry.get("details", ""),
            "created_at": entry.get("timestamp", ""),
        }
        for idx, entry in enumerate(i.timeline or [])
    ]


# ═══════════════════════════════════════════════════════════════════
#  SOAR: Playbooks
# ═══════════════════════════════════════════════════════════════════

@router.get("/playbooks")
def list_playbooks(
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Playbook).order_by(Playbook.name)
    if tid is not None:
        q = q.where(Playbook.tenant_id == tid)
    return [_playbook_to_response(p) for p in db.execute(q).scalars().all()]


@router.post("/playbooks")
def create_playbook(
    pb: PlaybookCreate,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    p = Playbook(
        tenant_id=tenant.id,
        name=pb.name,
        description=pb.description,
        trigger_type=pb.trigger_type,
        trigger_conditions=pb.trigger_conditions,
        steps=pb.steps,
        enabled=pb.enabled,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return _playbook_to_response(p)


@router.get("/playbooks/runs")
def list_playbook_runs(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(PlaybookRun).order_by(desc(PlaybookRun.started_at))
    if tid is not None:
        q = q.where(PlaybookRun.tenant_id == tid)
    q = q.limit(limit)
    return [_run_to_response(r) for r in db.execute(q).scalars().all()]


@router.get("/playbooks/{playbook_id}")
def get_playbook(
    playbook_id: int,
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(Playbook).where(Playbook.id == playbook_id)
    if tid is not None:
        q = q.where(Playbook.tenant_id == tid)
    p = db.execute(q).scalar_one_or_none()
    if not p:
        raise HTTPException(404, "Playbook not found")
    return _playbook_to_response(p)


@router.post("/playbooks/trigger")
async def trigger_playbook(
    body: PlaybookTrigger,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    if not tenant:
        raise HTTPException(403, "Tenant required")
    try:
        pb_id = int(body.playbook_id)
    except (ValueError, TypeError):
        raise HTTPException(400, "Invalid playbook_id")
    playbook = db.execute(
        select(Playbook).where(Playbook.id == pb_id, Playbook.tenant_id == tenant.id)
    ).scalar_one_or_none()
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    incident_id = body.incident_id
    run = PlaybookRun(
        tenant_id=tenant.id,
        playbook_id=pb_id,
        incident_id=incident_id,
        status=PlaybookStatus.RUNNING,
    )
    db.add(run)
    db.flush()

    context = {"tenant_id": tenant.id, "triggered_by": current_user.username}
    if incident_id:
        incident = db.execute(
            select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant.id)
        ).scalar_one_or_none()
        if incident:
            context.update({
                "incident_id": incident.id,
                "title": incident.title,
                "severity": incident.severity.value,
            })
    if body.alert_id:
        try:
            alert = db.execute(
                select(Alert).where(Alert.id == int(body.alert_id), Alert.tenant_id == tenant.id)
            ).scalar_one_or_none()
            if alert and alert.ioc_data:
                context.update(alert.ioc_data)
        except (ValueError, TypeError):
            pass

    try:
        result = await execute_playbook(
            {"name": playbook.name, "steps": playbook.steps or []}, context
        )
        run.status = PlaybookStatus.COMPLETED if result.get("status") == "completed" else PlaybookStatus.FAILED
        run.step_results = result.get("results", [])
    except Exception as e:
        run.status = PlaybookStatus.FAILED
        run.error = str(e)

    run.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(run)
    return _run_to_response(run)


@router.post("/playbooks/{playbook_id}/run")
async def run_playbook(
    playbook_id: int,
    incident_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    return await trigger_playbook(
        PlaybookTrigger(playbook_id=str(playbook_id), incident_id=incident_id),
        current_user, tenant, db,
    )


# ═══════════════════════════════════════════════════════════════════
#  Threat Intel
# ═══════════════════════════════════════════════════════════════════

@router.get("/threat-intel/lookup", response_model=ThreatLookupResult)
async def threat_intel_lookup(
    value: str = Query(...),
    current_user: User = Depends(get_current_user),
):
    ioc_type = "ip"
    if "." in value and any(c.isalpha() for c in value):
        ioc_type = "domain"
    elif len(value) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        ioc_type = "hash"
    result = await enrich_ioc(value, ioc_type)
    sources = []
    if result.get("virustotal"):
        sources.append({"name": "VirusTotal", **result["virustotal"]})
    if result.get("abuseipdb"):
        sources.append({"name": "AbuseIPDB", **result["abuseipdb"]})
    return {
        "query": value,
        "type": ioc_type,
        "found": result.get("verdict") not in (None, "clean", "unknown"),
        "value": value,
        "sources": sources,
        "results": sources,
    }


@router.get("/threat-intel/iocs")
def list_iocs(current_user: User = Depends(get_current_user)):
    return []


@router.get("/threat-intel/feeds")
def list_threat_feeds(current_user: User = Depends(get_current_user)):
    return [
        {
            "id": "vt",
            "name": "VirusTotal",
            "provider": "Google",
            "feed_type": "json",
            "url": "https://virustotal.com",
            "enabled": bool(settings.VIRUSTOTAL_API_KEY),
            "ioc_count": 0,
            "fetch_interval_minutes": 60,
            "status": "active" if settings.VIRUSTOTAL_API_KEY else "disabled",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
        {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "provider": "AbuseIPDB",
            "feed_type": "json",
            "url": "https://abuseipdb.com",
            "enabled": bool(settings.ABUSEIPDB_API_KEY),
            "ioc_count": 0,
            "fetch_interval_minutes": 60,
            "status": "active" if settings.ABUSEIPDB_API_KEY else "disabled",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    ]


# ═══════════════════════════════════════════════════════════════════
#  Agents (placeholder — agent SDK not yet implemented)
# ═══════════════════════════════════════════════════════════════════

@router.get("/agents")
def list_agents(current_user: User = Depends(get_current_user)):
    return []


@router.get("/agents/{agent_id}")
def get_agent(agent_id: str, current_user: User = Depends(get_current_user)):
    raise HTTPException(404, "Agent not found (agent SDK not yet deployed)")


# ═══════════════════════════════════════════════════════════════════
#  Users
# ═══════════════════════════════════════════════════════════════════

@router.get("/users")
def list_users(
    current_user: User = Depends(get_current_user),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tid = _tenant_id(tenant, current_user)
    q = select(User).order_by(User.username)
    if tid is not None:
        q = q.where(User.tenant_id == tid)
    return [_user_to_response(u) for u in db.execute(q).scalars().all()]


@router.post("/users")
def create_user_endpoint(
    body: UserCreate,
    current_user: User = Depends(require_role(UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN)),
    tenant: Optional[Tenant] = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    existing = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if existing:
        raise HTTPException(400, "Username already exists")
    try:
        role = UserRole(body.role)
    except ValueError:
        role = UserRole.ANALYST
    u = User(
        tenant_id=tenant.id if tenant else current_user.tenant_id,
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        role=role,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return _user_to_response(u)


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    body: dict,
    current_user: User = Depends(require_role(UserRole.SUPER_ADMIN, UserRole.TENANT_ADMIN)),
    db: Session = Depends(get_db),
):
    u = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found")
    for key in ("email", "is_active"):
        if key in body:
            setattr(u, key, body[key])
    if "role" in body:
        try:
            u.role = UserRole(body["role"])
        except ValueError:
            pass
    db.commit()
    db.refresh(u)
    return _user_to_response(u)


# ═══════════════════════════════════════════════════════════════════
#  Tenants (super-admin)
# ═══════════════════════════════════════════════════════════════════

@router.get("/tenants")
def list_tenants(
    current_user: User = Depends(require_role(UserRole.SUPER_ADMIN)),
    db: Session = Depends(get_db),
):
    tenants = db.execute(select(Tenant).order_by(Tenant.name)).scalars().all()
    return [
        {
            "id": t.id,
            "slug": t.slug,
            "name": t.name,
            "plan": t.plan.value if t.plan else "trial",
            "is_active": t.is_active,
            "ingest_token": t.ingest_token,
            "created_at": t.created_at,
        }
        for t in tenants
    ]


# ═══════════════════════════════════════════════════════════════════
#  Ingest via tenant token (for agents/syslog forwarders)
# ═══════════════════════════════════════════════════════════════════

@router.post("/ingest/event")
def ingest_via_token(
    request: Request,
    body: dict,
    db: Session = Depends(get_db),
):
    token = request.headers.get("X-Ingest-Token") or request.headers.get("x-ingest-token")
    if not token:
        raise HTTPException(401, "Missing X-Ingest-Token")
    from core.auth import get_tenant_by_ingest_token
    tenant = get_tenant_by_ingest_token(token, db)
    if not tenant:
        raise HTTPException(401, "Invalid ingest token")
    raw_log = body.get("raw_log") or body.get("message") or ""
    if not raw_log:
        raise HTTPException(400, "raw_log required")
    return ingest_log(db, raw_log, tenant.id, body.get("source_id"))

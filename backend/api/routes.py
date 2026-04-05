"""API routes for CyberNest."""

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from core.database import get_db
from core.models import (
    Event, Alert, AlertStatus, DetectionRule, LogSource,
    Incident, IncidentStatus, Playbook, PlaybookRun, PlaybookStatus, User, Severity,
)
from core.schemas import (
    EventCreate, EventResponse, EventQuery, AlertResponse, AlertUpdate,
    LogSourceCreate, LogSourceResponse, RuleCreate,
    IncidentCreate, IncidentResponse, IncidentUpdate,
    PlaybookResponse, PlaybookRunResponse, DashboardStats,
    UserCreate, UserResponse, Token,
)
from core.auth import hash_password, verify_password, create_access_token
from siem.ingest import ingest_log, ingest_batch
from soar.case_manager import create_incident, update_incident_status, add_timeline_entry
from soar.playbook_engine import execute_playbook

router = APIRouter()


# ─── Auth ───

@router.post("/auth/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.execute(select(User).where(User.username == user.username)).scalar_one_or_none()
    if existing:
        raise HTTPException(400, "Username already exists")
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
        role=user.role,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.post("/auth/login", response_model=Token)
def login(username: str = Query(...), password: str = Query(...), db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token}


# ─── Dashboard ───

@router.get("/dashboard/stats", response_model=DashboardStats)
def dashboard_stats(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_events = db.execute(select(func.count(Event.id))).scalar() or 0
    total_alerts = db.execute(select(func.count(Alert.id))).scalar() or 0
    open_alerts = db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.NEW)
    ).scalar() or 0
    critical_alerts = db.execute(
        select(func.count(Alert.id)).where(Alert.severity == Severity.CRITICAL)
    ).scalar() or 0
    active_incidents = db.execute(
        select(func.count(Incident.id)).where(Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS]))
    ).scalar() or 0
    playbook_runs = db.execute(
        select(func.count(PlaybookRun.id)).where(PlaybookRun.started_at >= today_start)
    ).scalar() or 0

    # Recent alerts
    recent_alerts = db.execute(
        select(Alert).order_by(desc(Alert.created_at)).limit(10)
    ).scalars().all()

    # Alerts by severity
    severity_counts = {}
    for sev in Severity:
        count = db.execute(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        ).scalar() or 0
        severity_counts[sev.value] = count

    return DashboardStats(
        total_events=total_events,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        active_incidents=active_incidents,
        playbook_runs_today=playbook_runs,
        events_per_hour=[],
        alerts_by_severity=severity_counts,
        top_source_ips=[],
        recent_alerts=recent_alerts,
    )


# ─── SIEM: Events ───

@router.post("/events/ingest")
def ingest_event(event: EventCreate, db: Session = Depends(get_db)):
    result = ingest_log(db, event.raw_log, event.source_id)
    return result


@router.post("/events/ingest/batch")
def ingest_events_batch(logs: list[str], db: Session = Depends(get_db)):
    result = ingest_batch(db, logs)
    return result


@router.get("/events", response_model=list[EventResponse])
def list_events(
    limit: int = Query(100, le=10000),
    offset: int = 0,
    severity: str = None,
    src_ip: str = None,
    dst_ip: str = None,
    search: str = None,
    db: Session = Depends(get_db),
):
    query = select(Event).order_by(desc(Event.timestamp))
    if severity:
        query = query.where(Event.severity == Severity(severity))
    if src_ip:
        query = query.where(Event.src_ip == src_ip)
    if dst_ip:
        query = query.where(Event.dst_ip == dst_ip)
    if search:
        query = query.where(Event.raw_log.contains(search))
    query = query.offset(offset).limit(limit)
    return db.execute(query).scalars().all()


@router.get("/events/{event_id}", response_model=EventResponse)
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.execute(select(Event).where(Event.id == event_id)).scalar_one_or_none()
    if not event:
        raise HTTPException(404, "Event not found")
    return event


# ─── SIEM: Alerts ───

@router.get("/alerts", response_model=list[AlertResponse])
def list_alerts(
    status: str = None,
    severity: str = None,
    limit: int = Query(50, le=1000),
    db: Session = Depends(get_db),
):
    query = select(Alert).order_by(desc(Alert.created_at))
    if status:
        query = query.where(Alert.status == AlertStatus(status))
    if severity:
        query = query.where(Alert.severity == Severity(severity))
    query = query.limit(limit)
    return db.execute(query).scalars().all()


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertResponse)
def update_alert(alert_id: int, update: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.execute(select(Alert).where(Alert.id == alert_id)).scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    if update.status:
        alert.status = AlertStatus(update.status)
    if update.assigned_to is not None:
        alert.assigned_to = update.assigned_to
    db.commit()
    db.refresh(alert)
    return alert


# ─── SIEM: Detection Rules ───

@router.get("/rules")
def list_rules(db: Session = Depends(get_db)):
    return db.execute(select(DetectionRule).order_by(DetectionRule.name)).scalars().all()


@router.post("/rules")
def create_rule(rule: RuleCreate, db: Session = Depends(get_db)):
    db_rule = DetectionRule(
        name=rule.name,
        description=rule.description,
        severity=Severity(rule.severity),
        logic=rule.logic,
        mitre_tactic=rule.mitre_tactic,
        mitre_technique=rule.mitre_technique,
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule


# ─── SIEM: Log Sources ───

@router.get("/sources", response_model=list[LogSourceResponse])
def list_sources(db: Session = Depends(get_db)):
    return db.execute(select(LogSource).order_by(LogSource.name)).scalars().all()


@router.post("/sources", response_model=LogSourceResponse)
def create_source(source: LogSourceCreate, db: Session = Depends(get_db)):
    db_source = LogSource(**source.model_dump())
    db.add(db_source)
    db.commit()
    db.refresh(db_source)
    return db_source


# ─── SOAR: Incidents ───

@router.get("/incidents", response_model=list[IncidentResponse])
def list_incidents(
    status: str = None,
    limit: int = Query(50, le=500),
    db: Session = Depends(get_db),
):
    query = select(Incident).order_by(desc(Incident.created_at))
    if status:
        query = query.where(Incident.status == status)
    query = query.limit(limit)
    return db.execute(query).scalars().all()


@router.post("/incidents", response_model=IncidentResponse)
def create_new_incident(data: IncidentCreate, db: Session = Depends(get_db)):
    incident = create_incident(
        db, data.title, data.severity, data.description, data.assigned_to, data.alert_ids
    )
    return incident


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, update: IncidentUpdate, db: Session = Depends(get_db)):
    if update.status:
        incident = update_incident_status(db, incident_id, update.status)
    else:
        incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
        if not incident:
            raise HTTPException(404, "Incident not found")
        if update.assigned_to is not None:
            incident.assigned_to = update.assigned_to
        if update.description is not None:
            incident.description = update.description
        if update.tags is not None:
            incident.tags = update.tags
        db.commit()
    return incident


@router.post("/incidents/{incident_id}/timeline")
def add_incident_timeline_entry(
    incident_id: int, action: str = Query(...), details: str = Query(...),
    db: Session = Depends(get_db),
):
    incident = add_timeline_entry(db, incident_id, action, details)
    return {"status": "ok", "timeline_count": len(incident.timeline)}


# ─── SOAR: Playbooks ───

@router.get("/playbooks", response_model=list[PlaybookResponse])
def list_playbooks(db: Session = Depends(get_db)):
    return db.execute(select(Playbook).order_by(Playbook.name)).scalars().all()


@router.post("/playbooks/{playbook_id}/run")
async def run_playbook(
    playbook_id: int,
    incident_id: int = None,
    db: Session = Depends(get_db),
):
    playbook = db.execute(select(Playbook).where(Playbook.id == playbook_id)).scalar_one_or_none()
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    run = PlaybookRun(
        playbook_id=playbook_id,
        incident_id=incident_id,
        status=PlaybookStatus.RUNNING,
    )
    db.add(run)
    db.flush()

    context = {}
    if incident_id:
        incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
        if incident:
            context["incident_id"] = incident.id
            context["title"] = incident.title
            context["severity"] = incident.severity.value

    exec_result = await execute_playbook(
        {"name": playbook.name, "steps": playbook.steps},
        context,
    )

    run.status = PlaybookStatus.COMPLETED if exec_result["status"] == "completed" else PlaybookStatus.FAILED
    run.step_results = exec_result["results"]
    run.completed_at = datetime.now(timezone.utc)
    db.commit()

    return exec_result


@router.get("/playbooks/runs", response_model=list[PlaybookRunResponse])
def list_playbook_runs(limit: int = 20, db: Session = Depends(get_db)):
    return db.execute(
        select(PlaybookRun).order_by(desc(PlaybookRun.started_at)).limit(limit)
    ).scalars().all()

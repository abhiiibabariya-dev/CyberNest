"""API routes for CyberNest."""

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.models import (
    Event, Alert, AlertStatus, DetectionRule, LogSource,
    Incident, Playbook, PlaybookRun, PlaybookStatus, User, Severity,
)
from core.schemas import (
    EventCreate, EventResponse, EventQuery, AlertResponse, AlertUpdate,
    LogSourceCreate, LogSourceResponse, RuleCreate,
    IncidentCreate, IncidentResponse, IncidentUpdate,
    PlaybookResponse, PlaybookRunResponse, DashboardStats,
    UserCreate, UserResponse, Token,
)
from core.auth import hash_password, verify_password, create_access_token, get_current_user
from siem.ingest import ingest_log, ingest_batch
from soar.case_manager import create_incident, update_incident_status, add_timeline_entry
from soar.playbook_engine import execute_playbook

router = APIRouter()


# ─── Auth ───

@router.post("/auth/register", response_model=UserResponse)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.username == user.username))
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Username already exists")
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
        role=user.role,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


@router.post("/auth/login", response_model=Token)
async def login(username: str = Query(...), password: str = Query(...), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token}


# ─── Dashboard ───

@router.get("/dashboard/stats", response_model=DashboardStats)
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_events = (await db.execute(func.count(Event.id))).scalar() or 0
    total_alerts = (await db.execute(func.count(Alert.id))).scalar() or 0
    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.NEW)
    )).scalar() or 0
    critical_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == Severity.CRITICAL)
    )).scalar() or 0
    active_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status.in_(["open", "in_progress"]))
    )).scalar() or 0
    playbook_runs = (await db.execute(
        select(func.count(PlaybookRun.id)).where(PlaybookRun.started_at >= today_start)
    )).scalar() or 0

    # Recent alerts
    recent = await db.execute(
        select(Alert).order_by(desc(Alert.created_at)).limit(10)
    )
    recent_alerts = recent.scalars().all()

    # Alerts by severity
    severity_counts = {}
    for sev in Severity:
        count = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )).scalar() or 0
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
async def ingest_event(event: EventCreate, db: AsyncSession = Depends(get_db)):
    result = await ingest_log(db, event.raw_log, event.source_id)
    return result


@router.post("/events/ingest/batch")
async def ingest_events_batch(logs: list[str], db: AsyncSession = Depends(get_db)):
    result = await ingest_batch(db, logs)
    return result


@router.get("/events", response_model=list[EventResponse])
async def list_events(
    limit: int = Query(100, le=10000),
    offset: int = 0,
    severity: str = None,
    src_ip: str = None,
    dst_ip: str = None,
    search: str = None,
    db: AsyncSession = Depends(get_db),
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
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/events/{event_id}", response_model=EventResponse)
async def get_event(event_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(404, "Event not found")
    return event


# ─── SIEM: Alerts ───

@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    status: str = None,
    severity: str = None,
    limit: int = Query(50, le=1000),
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert).order_by(desc(Alert.created_at))
    if status:
        query = query.where(Alert.status == AlertStatus(status))
    if severity:
        query = query.where(Alert.severity == Severity(severity))
    query = query.limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertResponse)
async def update_alert(alert_id: int, update: AlertUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    if update.status:
        alert.status = AlertStatus(update.status)
    if update.assigned_to is not None:
        alert.assigned_to = update.assigned_to
    await db.commit()
    await db.refresh(alert)
    return alert


# ─── SIEM: Detection Rules ───

@router.get("/rules")
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.name))
    return result.scalars().all()


@router.post("/rules")
async def create_rule(rule: RuleCreate, db: AsyncSession = Depends(get_db)):
    db_rule = DetectionRule(
        name=rule.name,
        description=rule.description,
        severity=Severity(rule.severity),
        logic=rule.logic,
        mitre_tactic=rule.mitre_tactic,
        mitre_technique=rule.mitre_technique,
    )
    db.add(db_rule)
    await db.commit()
    await db.refresh(db_rule)
    return db_rule


# ─── SIEM: Log Sources ───

@router.get("/sources", response_model=list[LogSourceResponse])
async def list_sources(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LogSource).order_by(LogSource.name))
    return result.scalars().all()


@router.post("/sources", response_model=LogSourceResponse)
async def create_source(source: LogSourceCreate, db: AsyncSession = Depends(get_db)):
    db_source = LogSource(**source.model_dump())
    db.add(db_source)
    await db.commit()
    await db.refresh(db_source)
    return db_source


# ─── SOAR: Incidents ───

@router.get("/incidents", response_model=list[IncidentResponse])
async def list_incidents(
    status: str = None,
    limit: int = Query(50, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident).order_by(desc(Incident.created_at))
    if status:
        query = query.where(Incident.status == status)
    query = query.limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/incidents", response_model=IncidentResponse)
async def create_new_incident(data: IncidentCreate, db: AsyncSession = Depends(get_db)):
    incident = await create_incident(
        db, data.title, data.severity, data.description, data.assigned_to, data.alert_ids
    )
    return incident


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentResponse)
async def update_incident(incident_id: int, update: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    if update.status:
        incident = await update_incident_status(db, incident_id, update.status)
    else:
        result = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = result.scalar_one_or_none()
        if not incident:
            raise HTTPException(404, "Incident not found")
        if update.assigned_to is not None:
            incident.assigned_to = update.assigned_to
        if update.description is not None:
            incident.description = update.description
        if update.tags is not None:
            incident.tags = update.tags
        await db.commit()
    return incident


@router.post("/incidents/{incident_id}/timeline")
async def add_incident_timeline(
    incident_id: int, action: str = Query(...), details: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    incident = await add_timeline_entry(db, incident_id, action, details)
    return {"status": "ok", "timeline_count": len(incident.timeline)}


# ─── SOAR: Playbooks ───

@router.get("/playbooks", response_model=list[PlaybookResponse])
async def list_playbooks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Playbook).order_by(Playbook.name))
    return result.scalars().all()


@router.post("/playbooks/{playbook_id}/run")
async def run_playbook(
    playbook_id: int,
    incident_id: int = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    # Create run record
    run = PlaybookRun(
        playbook_id=playbook_id,
        incident_id=incident_id,
        status=PlaybookStatus.RUNNING,
    )
    db.add(run)
    await db.flush()

    # Build context from incident if available
    context = {}
    if incident_id:
        inc_result = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = inc_result.scalar_one_or_none()
        if incident:
            context["incident_id"] = incident.id
            context["title"] = incident.title
            context["severity"] = incident.severity.value

    # Execute playbook
    exec_result = await execute_playbook(
        {"name": playbook.name, "steps": playbook.steps},
        context,
    )

    run.status = PlaybookStatus.COMPLETED if exec_result["status"] == "completed" else PlaybookStatus.FAILED
    run.step_results = exec_result["results"]
    run.completed_at = datetime.now(timezone.utc)
    await db.commit()

    return exec_result


@router.get("/playbooks/runs", response_model=list[PlaybookRunResponse])
async def list_playbook_runs(limit: int = 20, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PlaybookRun).order_by(desc(PlaybookRun.started_at)).limit(limit)
    )
    return result.scalars().all()

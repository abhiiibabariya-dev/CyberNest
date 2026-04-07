"""CyberNest — Case / Incident management API routes."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.auth import get_current_user, require_analyst
from app.models.auth import User
from app.models.siem import Alert
from app.models.soar import Incident, CaseTask, Observable
from app.models.enums import Severity, IncidentStatus
from app.schemas.soar import (
    IncidentCreate, IncidentResponse, IncidentUpdate,
    CaseTaskCreate, CaseTaskResponse, CaseTaskUpdate,
    ObservableCreate, ObservableResponse,
)

router = APIRouter(prefix="/cases", tags=["Cases / Incidents"])


async def _generate_case_id(db: AsyncSession) -> str:
    result = await db.execute(select(func.count()).select_from(Incident))
    count = (result.scalar() or 0) + 1
    return f"CN-INC-{count:05d}"


@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    severity: Severity | None = None,
    status: IncidentStatus | None = None,
    assignee_id: uuid.UUID | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    query = (
        select(Incident)
        .options(selectinload(Incident.tasks), selectinload(Incident.observables))
        .order_by(desc(Incident.created_at))
        .limit(limit).offset(offset)
    )
    if severity:
        query = query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
    if assignee_id:
        query = query.where(Incident.assignee_id == assignee_id)

    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=IncidentResponse, status_code=201)
async def create_incident(
    data: IncidentCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    case_id = await _generate_case_id(db)
    now = datetime.now(timezone.utc)

    incident = Incident(
        case_id=case_id,
        title=data.title,
        description=data.description,
        severity=data.severity,
        template=data.template,
        assignee_id=data.assignee_id,
        tags=data.tags,
        mitre_tactics=data.mitre_tactics,
        mitre_techniques=data.mitre_techniques,
        timeline=[{
            "timestamp": now.isoformat(),
            "action": "created",
            "user": current_user.full_name,
            "detail": f"Case {case_id} created",
        }],
    )
    db.add(incident)
    await db.flush()

    # Link alerts if provided
    if data.alert_ids:
        for alert_id in data.alert_ids:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if alert:
                alert.incident_id = incident.id

    await db.refresh(incident)
    return incident


@router.get("/{case_id}", response_model=IncidentResponse)
async def get_incident(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(
        select(Incident)
        .options(selectinload(Incident.tasks), selectinload(Incident.observables))
        .where(Incident.case_id == case_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Case not found")
    return incident


@router.patch("/{case_id}", response_model=IncidentResponse)
async def update_incident(
    case_id: str,
    data: IncidentUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    result = await db.execute(select(Incident).where(Incident.case_id == case_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Case not found")

    now = datetime.now(timezone.utc)
    changes = []

    for field, value in data.model_dump(exclude_unset=True).items():
        old_value = getattr(incident, field)
        if old_value != value:
            setattr(incident, field, value)
            changes.append(f"{field}: {old_value} → {value}")

    if data.status and data.status in (IncidentStatus.CLOSED, IncidentStatus.RECOVERED):
        incident.closed_at = now
        if incident.created_at:
            incident.time_to_resolve_ms = int((now - incident.created_at).total_seconds() * 1000)

    if changes:
        timeline = incident.timeline or []
        timeline.append({
            "timestamp": now.isoformat(),
            "action": "updated",
            "user": current_user.full_name,
            "detail": "; ".join(changes),
        })
        incident.timeline = timeline

    incident.updated_at = now
    await db.flush()
    await db.refresh(incident)
    return incident


# ── Case Tasks ──

@router.post("/{case_id}/tasks", response_model=CaseTaskResponse, status_code=201)
async def create_task(
    case_id: str,
    data: CaseTaskCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    result = await db.execute(select(Incident).where(Incident.case_id == case_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Case not found")

    task_count = await db.execute(
        select(func.count()).where(CaseTask.incident_id == incident.id)
    )
    order = (task_count.scalar() or 0) + 1

    task = CaseTask(
        incident_id=incident.id,
        title=data.title,
        description=data.description,
        assignee_id=data.assignee_id,
        due_date=data.due_date,
        order=order,
    )
    db.add(task)
    await db.flush()
    await db.refresh(task)
    return task


@router.get("/{case_id}/tasks", response_model=list[CaseTaskResponse])
async def list_tasks(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Incident).where(Incident.case_id == case_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Case not found")

    tasks = await db.execute(
        select(CaseTask).where(CaseTask.incident_id == incident.id).order_by(CaseTask.order)
    )
    return tasks.scalars().all()


# ── Observables / IOCs ──

@router.post("/{case_id}/observables", response_model=ObservableResponse, status_code=201)
async def add_observable(
    case_id: str,
    data: ObservableCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    result = await db.execute(select(Incident).where(Incident.case_id == case_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Case not found")

    observable = Observable(
        incident_id=incident.id,
        ioc_type=data.ioc_type,
        value=data.value,
        description=data.description,
        tags=data.tags,
        tlp=data.tlp,
    )
    db.add(observable)
    await db.flush()
    await db.refresh(observable)
    return observable


@router.get("/{case_id}/observables", response_model=list[ObservableResponse])
async def list_observables(
    case_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Incident).where(Incident.case_id == case_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Case not found")

    observables = await db.execute(
        select(Observable).where(Observable.incident_id == incident.id)
    )
    return observables.scalars().all()

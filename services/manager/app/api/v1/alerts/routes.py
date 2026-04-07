"""CyberNest — Alert management API routes."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user, require_analyst
from app.models.auth import User
from app.models.siem import Alert
from app.models.enums import Severity, AlertStatus
from app.schemas.siem import AlertResponse, AlertUpdate

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=list[AlertResponse])
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    rule_id: str | None = None,
    source_ip: str | None = None,
    assignee_id: uuid.UUID | None = None,
    from_time: str | None = Query(None, alias="from"),
    to_time: str | None = Query(None, alias="to"),
    limit: int = Query(100, le=1000),
    offset: int = 0,
):
    query = select(Alert).order_by(desc(Alert.created_at)).limit(limit).offset(offset)

    if severity:
        query = query.where(Alert.severity == severity)
    if status:
        query = query.where(Alert.status == status)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
    if assignee_id:
        query = query.where(Alert.assignee_id == assignee_id)
    if from_time:
        query = query.where(Alert.created_at >= from_time)
    if to_time:
        query = query.where(Alert.created_at <= to_time)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats")
async def alert_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Alert statistics for dashboard widgets."""
    # Count by severity
    severity_counts = {}
    for sev in Severity:
        result = await db.execute(
            select(func.count()).where(Alert.severity == sev, Alert.status == AlertStatus.NEW)
        )
        severity_counts[sev.value] = result.scalar() or 0

    # Count by status
    status_counts = {}
    for st in AlertStatus:
        result = await db.execute(
            select(func.count()).where(Alert.status == st)
        )
        status_counts[st.value] = result.scalar() or 0

    return {
        "by_severity": severity_counts,
        "by_status": status_counts,
        "total_new": status_counts.get("new", 0),
        "total_open": sum(status_counts.get(s, 0) for s in ["new", "acknowledged", "investigating"]),
    }


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: uuid.UUID,
    data: AlertUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.now(timezone.utc)

    if data.status is not None:
        alert.status = data.status
        if data.status == AlertStatus.ACKNOWLEDGED and not alert.acknowledged_at:
            alert.acknowledged_at = now
            # Calculate time to respond
            if alert.created_at:
                alert.time_to_respond_ms = int((now - alert.created_at).total_seconds() * 1000)
        elif data.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
            alert.resolved_at = now

    if data.assignee_id is not None:
        alert.assignee_id = data.assignee_id
    if data.incident_id is not None:
        alert.incident_id = data.incident_id

    alert.updated_at = now
    await db.flush()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/escalate", response_model=AlertResponse)
async def escalate_alert(
    alert_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    """Escalate alert to incident."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = AlertStatus.ESCALATED
    alert.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(alert)
    return alert

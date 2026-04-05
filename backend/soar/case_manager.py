"""Case/Incident management for SOAR."""

from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from core.models import Incident, Alert, IncidentStatus, Severity


async def create_incident(
    db: AsyncSession,
    title: str,
    severity: str,
    description: str = None,
    assigned_to: str = None,
    alert_ids: list[int] = None,
) -> Incident:
    """Create a new incident, optionally linking alerts."""
    incident = Incident(
        title=title,
        description=description,
        severity=Severity(severity),
        status=IncidentStatus.OPEN,
        assigned_to=assigned_to,
        timeline=[
            {
                "action": "created",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": f"Incident created: {title}",
            }
        ],
    )
    db.add(incident)
    await db.flush()

    # Link alerts to incident
    if alert_ids:
        result = await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))
        alerts = result.scalars().all()
        for alert in alerts:
            alert.incident_id = incident.id

    await db.commit()
    logger.info(f"Incident created: #{incident.id} - {title}")
    return incident


async def update_incident_status(
    db: AsyncSession, incident_id: int, new_status: str, details: str = None
) -> Incident:
    """Update incident status and add timeline entry."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    old_status = incident.status
    incident.status = IncidentStatus(new_status)

    timeline_entry = {
        "action": "status_change",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "from": old_status.value,
        "to": new_status,
        "details": details or f"Status changed from {old_status.value} to {new_status}",
    }
    incident.timeline = incident.timeline + [timeline_entry]

    if new_status == "closed":
        incident.closed_at = datetime.now(timezone.utc)

    await db.commit()
    return incident


async def add_timeline_entry(
    db: AsyncSession, incident_id: int, action: str, details: str
) -> Incident:
    """Add a custom timeline entry to an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    entry = {
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    incident.timeline = incident.timeline + [entry]
    await db.commit()
    return incident

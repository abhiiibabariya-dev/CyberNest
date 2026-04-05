"""Case/Incident management for SOAR."""

from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from loguru import logger

from core.models import Incident, Alert, IncidentStatus, Severity


def create_incident(
    db: Session,
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
    db.flush()

    if alert_ids:
        alerts = db.execute(select(Alert).where(Alert.id.in_(alert_ids))).scalars().all()
        for alert in alerts:
            alert.incident_id = incident.id

    db.commit()
    logger.info(f"Incident created: #{incident.id} - {title}")
    return incident


def update_incident_status(
    db: Session, incident_id: int, new_status: str, details: str = None
) -> Incident:
    """Update incident status and add timeline entry."""
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
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

    db.commit()
    return incident


def add_timeline_entry(
    db: Session, incident_id: int, action: str, details: str
) -> Incident:
    """Add a custom timeline entry to an incident."""
    incident = db.execute(select(Incident).where(Incident.id == incident_id)).scalar_one_or_none()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    entry = {
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    incident.timeline = incident.timeline + [entry]
    db.commit()
    return incident

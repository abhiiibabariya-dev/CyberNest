"""Case/Incident management — tenant-scoped."""
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

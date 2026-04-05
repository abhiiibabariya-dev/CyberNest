"""Log ingestion service - receives and processes incoming logs."""

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from loguru import logger

from core.models import Event, Alert, AlertStatus, Severity
from siem.parser import parse_log
from siem.detection import run_detection


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def ingest_log(db: Session, raw_log: str, source_id: int = None) -> dict:
    """Ingest a raw log: parse, store, and run detection."""
    parsed = parse_log(raw_log)

    event = Event(
        timestamp=datetime.now(timezone.utc),
        source_id=source_id,
        raw_log=raw_log,
        parsed=parsed,
        severity=SEVERITY_MAP.get(parsed.get("severity_raw", "info"), Severity.INFO),
        category=parsed.get("category"),
        src_ip=parsed.get("src_ip"),
        dst_ip=parsed.get("dst_ip"),
        hostname=parsed.get("hostname"),
        message=parsed.get("message"),
        mitre_tactic=parsed.get("mitre_tactic"),
        mitre_technique=parsed.get("mitre_technique"),
    )
    db.add(event)
    db.flush()

    event_data = {
        "id": event.id,
        "raw_log": raw_log,
        "src_ip": parsed.get("src_ip"),
        "dst_ip": parsed.get("dst_ip"),
        "hostname": parsed.get("hostname"),
        "message": parsed.get("message"),
        "category": parsed.get("category"),
        "severity": str(event.severity.value) if event.severity else "info",
    }

    triggered_alerts = run_detection(event_data)

    created_alerts = []
    for alert_data in triggered_alerts:
        alert = Alert(
            severity=SEVERITY_MAP.get(alert_data["severity"], Severity.MEDIUM),
            status=AlertStatus.NEW,
            title=alert_data["title"],
            description=alert_data["description"],
            source_event_ids=[event.id],
            ioc_data={
                "src_ip": parsed.get("src_ip"),
                "dst_ip": parsed.get("dst_ip"),
            },
        )
        db.add(alert)
        created_alerts.append(alert_data)

    db.commit()

    return {
        "event_id": event.id,
        "alerts_triggered": len(created_alerts),
        "alerts": created_alerts,
    }


def ingest_batch(db: Session, logs: list[str], source_id: int = None) -> dict:
    """Ingest a batch of raw logs."""
    results = []
    total_alerts = 0
    for raw_log in logs:
        result = ingest_log(db, raw_log, source_id)
        results.append(result)
        total_alerts += result["alerts_triggered"]
    return {
        "events_ingested": len(results),
        "alerts_triggered": total_alerts,
    }

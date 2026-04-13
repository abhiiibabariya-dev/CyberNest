"""Log ingestion — tenant-scoped parse, store, detect, broadcast."""
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

"""CyberNest — Dashboard statistics API routes."""

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user
from app.core.redis import redis_client
from app.core.elasticsearch import es_client
from app.models.auth import User
from app.models.siem import Alert, Agent, DetectionRule
from app.models.soar import Incident
from app.models.enums import Severity, AlertStatus, AgentStatus, IncidentStatus

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    # Event count from Elasticsearch
    total_events_24h = 0
    try:
        resp = await es_client.count(
            index="cybernest-events-*",
            body={"query": {"range": {"@timestamp": {"gte": last_24h.isoformat()}}}}
        )
        total_events_24h = resp.get("count", 0)
    except Exception:
        pass

    # Alert counts
    alert_24h = await db.execute(
        select(func.count()).where(Alert.created_at >= last_24h)
    )

    severity_counts = {}
    for sev in Severity:
        result = await db.execute(
            select(func.count()).where(
                Alert.severity == sev,
                Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING])
            )
        )
        severity_counts[sev.value] = result.scalar() or 0

    # Agent counts
    total_agents = await db.execute(select(func.count()).select_from(Agent))
    active_agents = await db.execute(
        select(func.count()).where(Agent.status == AgentStatus.ONLINE)
    )

    # Active incidents
    active_incidents = await db.execute(
        select(func.count()).where(
            Incident.status.in_([IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS, IncidentStatus.CONTAINED])
        )
    )

    # EPS from Redis
    eps = 0.0
    try:
        eps_val = await redis_client.get("stats:eps")
        eps = float(eps_val) if eps_val else 0.0
    except Exception:
        pass

    # Top attackers (last 24h)
    top_attackers = []
    try:
        resp = await es_client.search(
            index="cybernest-alerts-*",
            body={
                "size": 0,
                "query": {"range": {"@timestamp": {"gte": last_24h.isoformat()}}},
                "aggs": {"top_src": {"terms": {"field": "source.ip", "size": 10}}}
            }
        )
        top_attackers = [
            {"ip": b["key"], "count": b["doc_count"]}
            for b in resp.get("aggregations", {}).get("top_src", {}).get("buckets", [])
        ]
    except Exception:
        pass

    # Top rules fired
    top_rules = []
    result = await db.execute(
        select(
            Alert.rule_name,
            func.count().label("count")
        )
        .where(Alert.created_at >= last_24h, Alert.rule_name.isnot(None))
        .group_by(Alert.rule_name)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_rules = [{"rule": row[0], "count": row[1]} for row in result.all()]

    # Alert trend (hourly for last 24h)
    alert_trend = []
    for i in range(24):
        hour_start = last_24h + timedelta(hours=i)
        hour_end = hour_start + timedelta(hours=1)
        count = await db.execute(
            select(func.count()).where(
                Alert.created_at >= hour_start,
                Alert.created_at < hour_end,
            )
        )
        alert_trend.append({
            "hour": hour_start.strftime("%H:00"),
            "count": count.scalar() or 0,
        })

    # MITRE coverage
    mitre_coverage = {}
    result = await db.execute(select(DetectionRule.mitre_techniques).where(DetectionRule.enabled == True))
    for row in result.scalars().all():
        if row:
            for tech in row:
                mitre_coverage[tech] = mitre_coverage.get(tech, 0) + 1

    return {
        "total_events_24h": total_events_24h,
        "total_alerts_24h": alert_24h.scalar() or 0,
        "critical_alerts": severity_counts.get("critical", 0),
        "high_alerts": severity_counts.get("high", 0),
        "medium_alerts": severity_counts.get("medium", 0),
        "low_alerts": severity_counts.get("low", 0),
        "active_agents": active_agents.scalar() or 0,
        "total_agents": total_agents.scalar() or 0,
        "active_incidents": active_incidents.scalar() or 0,
        "events_per_second": eps,
        "top_attackers": top_attackers,
        "top_rules": top_rules,
        "alert_trend": alert_trend,
        "mitre_coverage": mitre_coverage,
    }

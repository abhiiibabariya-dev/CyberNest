"""
CyberNest Manager -- Dashboard router.

Provides aggregated statistics for the SOC dashboard and a live WebSocket
that broadcasts updated stats every 30 seconds.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user
from manager.config import get_settings
from manager.db.database import AsyncSessionLocal, get_db
from manager.db.models import (
    Agent,
    AgentStatusEnum,
    Alert,
    AlertSeverityEnum,
    AlertStatusEnum,
    Case,
    CaseStatusEnum,
    Rule,
)
from shared.utils.crypto import decode_jwt_token
from shared.utils.logger import get_logger

logger = get_logger("manager.dashboard")
settings = get_settings()

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats")
async def get_dashboard_stats(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return comprehensive dashboard statistics."""
    now = datetime.now(timezone.utc)
    h24_ago = now - timedelta(hours=24)

    stats = await _build_stats(db, now, h24_ago)
    return stats


async def _build_stats(db: AsyncSession, now: datetime, h24_ago: datetime) -> dict:
    """Build the full stats dict from DB and ES."""

    # Total events 24h (from ES)
    total_events_24h = 0
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
        if es:
            result = await es.count(
                index=settings.ES_INDEX_EVENTS,
                body={"query": {"range": {"@timestamp": {"gte": "now-24h"}}}},
            )
            total_events_24h = result.get("count", 0)
    except Exception:
        pass

    # Total alerts 24h
    alerts_24h_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= h24_ago)
    )
    total_alerts_24h = alerts_24h_result.scalar() or 0

    # Alerts by severity (24h)
    sev_result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.created_at >= h24_ago)
        .group_by(Alert.severity)
    )
    alerts_by_severity = {row[0].value: row[1] for row in sev_result.all()}

    # Alerts by status
    status_result = await db.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    )
    alerts_by_status = {row[0].value: row[1] for row in status_result.all()}

    # Top rules (by hit count)
    top_rules_result = await db.execute(
        select(Rule.id, Rule.name, Rule.hit_count, Rule.level)
        .where(Rule.hit_count > 0)
        .order_by(Rule.hit_count.desc())
        .limit(10)
    )
    top_rules = [
        {"id": str(row[0]), "name": row[1], "hit_count": row[2], "level": row[3]}
        for row in top_rules_result.all()
    ]

    # Top source IPs (24h)
    top_ips_result = await db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("cnt"))
        .where(and_(Alert.created_at >= h24_ago, Alert.source_ip.isnot(None)))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )
    top_source_ips = [
        {"ip": str(row[0]), "count": row[1]}
        for row in top_ips_result.all()
    ]

    # Events per hour (from ES)
    events_per_hour = []
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
        if es:
            result = await es.search(
                index=settings.ES_INDEX_EVENTS,
                body={
                    "size": 0,
                    "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
                    "aggs": {
                        "events_per_hour": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": "1h",
                            }
                        }
                    },
                },
            )
            buckets = result.get("aggregations", {}).get("events_per_hour", {}).get("buckets", [])
            events_per_hour = [
                {"hour": b["key_as_string"], "count": b["doc_count"]}
                for b in buckets
            ]
    except Exception:
        pass

    # Agent status
    agent_status_result = await db.execute(
        select(Agent.status, func.count(Agent.id)).group_by(Agent.status)
    )
    agent_status = {row[0].value: row[1] for row in agent_status_result.all()}

    # MITRE techniques (24h)
    mitre_result = await db.execute(
        select(Alert.mitre_technique, func.count(Alert.id).label("cnt"))
        .where(and_(Alert.created_at >= h24_ago, Alert.mitre_technique.isnot(None)))
        .group_by(Alert.mitre_technique)
        .order_by(func.count(Alert.id).desc())
        .limit(20)
    )
    mitre_techniques = [
        {"technique": row[0], "count": row[1]}
        for row in mitre_result.all()
    ]

    # Open cases
    open_cases_result = await db.execute(
        select(func.count(Case.id)).where(
            Case.status.in_([CaseStatusEnum.open, CaseStatusEnum.in_progress])
        )
    )
    open_cases = open_cases_result.scalar() or 0

    # MTTD (Mean Time to Detect) -- average time between event creation and alert creation
    # Approximated as the average time alerts spend in 'new' status
    # MTTR (Mean Time to Resolve)
    mttd_result = await db.execute(
        select(
            func.avg(
                func.extract("epoch", Alert.updated_at) - func.extract("epoch", Alert.created_at)
            )
        ).where(
            and_(
                Alert.status.in_([AlertStatusEnum.in_progress, AlertStatusEnum.resolved]),
                Alert.created_at >= h24_ago,
            )
        )
    )
    mttd_seconds = mttd_result.scalar()
    mttd_minutes = round(mttd_seconds / 60, 1) if mttd_seconds else 0

    mttr_result = await db.execute(
        select(
            func.avg(
                func.extract("epoch", Alert.updated_at) - func.extract("epoch", Alert.created_at)
            )
        ).where(
            and_(
                Alert.status == AlertStatusEnum.resolved,
                Alert.created_at >= h24_ago,
            )
        )
    )
    mttr_seconds = mttr_result.scalar()
    mttr_minutes = round(mttr_seconds / 60, 1) if mttr_seconds else 0

    return {
        "total_events_24h": total_events_24h,
        "total_alerts_24h": total_alerts_24h,
        "alerts_by_severity": alerts_by_severity,
        "alerts_by_status": alerts_by_status,
        "top_rules": top_rules,
        "top_source_ips": top_source_ips,
        "events_per_hour": events_per_hour,
        "agent_status": agent_status,
        "mitre_techniques": mitre_techniques,
        "open_cases": open_cases,
        "mttd_minutes": mttd_minutes,
        "mttr_minutes": mttr_minutes,
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Live WebSocket -- broadcasts stats every 30s
# ---------------------------------------------------------------------------

@router.websocket("/live")
async def dashboard_live(websocket: WebSocket):
    """WebSocket that broadcasts dashboard stats every 30 seconds."""
    await websocket.accept()

    # Authenticate
    token = websocket.query_params.get("token")
    if token:
        try:
            decode_jwt_token(token, settings.JWT_SECRET)
        except Exception:
            await websocket.close(code=4001, reason="Invalid token")
            return
    else:
        await websocket.close(code=4001, reason="Token required")
        return

    try:
        while True:
            try:
                now = datetime.now(timezone.utc)
                h24_ago = now - timedelta(hours=24)

                async with AsyncSessionLocal() as db:
                    stats = await _build_stats(db, now, h24_ago)

                await websocket.send_text(json.dumps(stats, default=str))
            except Exception as exc:
                logger.warning("dashboard stats broadcast failed", error=str(exc))

            await asyncio.sleep(30)
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass

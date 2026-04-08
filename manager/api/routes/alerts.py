"""
CyberNest Manager -- Alerts router.

Full alert management: list, detail, status update, assignment, comments,
case creation, stats, and live WebSocket streaming via Redis pub/sub.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, case, cast, func, select, update, String
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from shared.utils.crypto import decode_jwt_token
from manager.db.models import (
    Alert,
    AlertSeverityEnum,
    AlertStatusEnum,
    AuditLog,
    Case,
    CaseStatusEnum,
    CaseSeverityEnum,
    User,
)
from shared.utils.logger import get_logger

logger = get_logger("manager.alerts")
settings = get_settings()

router = APIRouter(prefix="/alerts", tags=["Alerts"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="new, in_progress, resolved, false_positive, escalated")


class AlertAssign(BaseModel):
    assignee_id: str = Field(..., description="UUID of the analyst to assign to")


class AlertComment(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)


class AlertToCaseRequest(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    rule_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    assignee: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    sort_by: str = Query("created_at", regex="^(created_at|severity|status|title)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List alerts with pagination and filters."""
    query = select(Alert)
    count_query = select(func.count(Alert.id))
    conditions = []

    if severity:
        try:
            sev = AlertSeverityEnum(severity)
            conditions.append(Alert.severity == sev)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")

    if status_filter:
        try:
            st = AlertStatusEnum(status_filter)
            conditions.append(Alert.status == st)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")

    if rule_id:
        try:
            conditions.append(Alert.rule_id == uuid.UUID(rule_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid rule_id UUID")

    if agent_id:
        try:
            conditions.append(Alert.agent_id == uuid.UUID(agent_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid agent_id UUID")

    if source_ip:
        conditions.append(cast(Alert.source_ip, String) == source_ip)

    if date_from:
        conditions.append(Alert.created_at >= date_from)

    if date_to:
        conditions.append(Alert.created_at <= date_to)

    if assignee:
        try:
            conditions.append(Alert.assignee == uuid.UUID(assignee))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid assignee UUID")

    if mitre_technique:
        conditions.append(Alert.mitre_technique == mitre_technique)

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    # Sorting
    sort_col = getattr(Alert, sort_by, Alert.created_at)
    if sort_order == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    # Pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "items": [_alert_to_dict(a) for a in alerts],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.get("/stats")
async def alert_stats(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert statistics: counts by severity/status, trend by hour (24h)."""
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)

    # Counts by severity
    sev_result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .where(Alert.created_at >= twenty_four_hours_ago)
        .group_by(Alert.severity)
    )
    by_severity = {row[0].value: row[1] for row in sev_result.all()}

    # Counts by status
    status_result = await db.execute(
        select(Alert.status, func.count(Alert.id))
        .group_by(Alert.status)
    )
    by_status = {row[0].value: row[1] for row in status_result.all()}

    # Trend by hour (24h)
    hourly_result = await db.execute(
        select(
            func.date_trunc("hour", Alert.created_at).label("hour"),
            func.count(Alert.id).label("count"),
        )
        .where(Alert.created_at >= twenty_four_hours_ago)
        .group_by("hour")
        .order_by("hour")
    )
    trend = [
        {"hour": row[0].isoformat() if row[0] else None, "count": row[1]}
        for row in hourly_result.all()
    ]

    # Total counts
    total_24h_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= twenty_four_hours_ago)
    )
    total_24h = total_24h_result.scalar() or 0

    return {
        "total_24h": total_24h,
        "by_severity": by_severity,
        "by_status": by_status,
        "hourly_trend": trend,
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get alert detail with related events from Elasticsearch (same source_ip +/- 5min)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_data = _alert_to_dict(alert)

    # Query ES for related events by source_ip within +/- 5min
    related_events = []
    try:
        es_client = getattr(db, "_request_app_state_es", None)
        # Access from the app state is not straightforward in a dependency;
        # we attempt to search ES if the alert has a source_ip
        if alert.source_ip:
            from manager.main import app
            es = getattr(app.state, "es", None)
            if es:
                alert_time = alert.created_at
                time_from = (alert_time - timedelta(minutes=5)).isoformat()
                time_to = (alert_time + timedelta(minutes=5)).isoformat()

                body = {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"source.ip": str(alert.source_ip)}},
                                {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}},
                            ]
                        }
                    },
                    "size": 50,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                }
                es_result = await es.search(
                    index=settings.ES_INDEX_EVENTS,
                    body=body,
                )
                related_events = [
                    hit["_source"] for hit in es_result.get("hits", {}).get("hits", [])
                ]
    except Exception as exc:
        logger.warning("failed to fetch related events from ES", error=str(exc))

    alert_data["related_events"] = related_events
    return alert_data


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: uuid.UUID,
    body: AlertStatusUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update alert status with timestamp tracking."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    try:
        new_status = AlertStatusEnum(body.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")

    old_status = alert.status
    alert.status = new_status
    alert.updated_at = datetime.now(timezone.utc)
    db.add(alert)

    # Audit
    audit = AuditLog(
        user_id=current_user.user_id,
        action="update_status",
        resource_type="alert",
        resource_id=str(alert_id),
        details={"old_status": old_status.value, "new_status": new_status.value},
    )
    db.add(audit)

    # Publish to Redis for live updates
    try:
        from manager.main import app
        redis = getattr(app.state, "redis", None)
        if redis:
            await redis.publish(
                "alerts:live",
                json.dumps({
                    "type": "status_change",
                    "alert_id": str(alert_id),
                    "old_status": old_status.value,
                    "new_status": new_status.value,
                    "updated_by": current_user.username,
                }),
            )
    except Exception:
        pass

    return _alert_to_dict(alert)


@router.patch("/{alert_id}/assign")
async def assign_alert(
    alert_id: uuid.UUID,
    body: AlertAssign,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Assign an alert to an analyst."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    try:
        assignee_uuid = uuid.UUID(body.assignee_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid assignee UUID")

    # Verify the assignee exists
    assignee_result = await db.execute(select(User).where(User.id == assignee_uuid))
    assignee_user = assignee_result.scalar_one_or_none()
    if assignee_user is None:
        raise HTTPException(status_code=404, detail="Assignee user not found")

    old_assignee = str(alert.assignee) if alert.assignee else None
    alert.assignee = assignee_uuid
    alert.updated_at = datetime.now(timezone.utc)

    if alert.status == AlertStatusEnum.new:
        alert.status = AlertStatusEnum.in_progress

    db.add(alert)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="assign",
        resource_type="alert",
        resource_id=str(alert_id),
        details={"old_assignee": old_assignee, "new_assignee": body.assignee_id},
    )
    db.add(audit)

    return _alert_to_dict(alert)


@router.post("/{alert_id}/comment")
async def add_alert_comment(
    alert_id: uuid.UUID,
    body: AlertComment,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a comment to an alert (stored in parsed_event JSONB)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    comment = {
        "author": current_user.username,
        "user_id": str(current_user.user_id),
        "content": body.content,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Store comments in the parsed_event JSONB under a "comments" key
    event_data = dict(alert.parsed_event) if alert.parsed_event else {}
    comments = event_data.get("comments", [])
    comments.append(comment)
    event_data["comments"] = comments
    alert.parsed_event = event_data
    alert.updated_at = datetime.now(timezone.utc)
    db.add(alert)

    return {"detail": "Comment added", "comment": comment}


@router.post("/{alert_id}/case")
async def create_case_from_alert(
    alert_id: uuid.UUID,
    body: AlertToCaseRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new case from an alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    if alert.case_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Alert is already linked to a case",
        )

    case_id_str = f"CASE-{uuid.uuid4().hex[:12].upper()}"
    severity_val = body.severity or alert.severity.value
    try:
        case_severity = CaseSeverityEnum(severity_val)
    except ValueError:
        case_severity = CaseSeverityEnum.medium

    new_case = Case(
        case_id=case_id_str,
        title=body.title or f"Case from alert: {alert.title}",
        description=body.description or alert.description or "",
        severity=case_severity,
        status=CaseStatusEnum.open,
        assignee=current_user.user_id,
        tags=body.tags,
    )
    db.add(new_case)
    await db.flush()

    alert.case_id = new_case.id
    alert.status = AlertStatusEnum.escalated
    alert.updated_at = datetime.now(timezone.utc)
    db.add(alert)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="create_case_from_alert",
        resource_type="case",
        resource_id=str(new_case.id),
        details={"alert_id": str(alert_id)},
    )
    db.add(audit)

    return {
        "case_id": str(new_case.id),
        "case_number": case_id_str,
        "alert_id": str(alert_id),
        "detail": "Case created from alert",
    }


@router.websocket("/live")
async def alerts_live(websocket: WebSocket):
    """WebSocket endpoint streaming new alerts via Redis pub/sub."""
    await websocket.accept()

    # Authenticate via query param token
    token = websocket.query_params.get("token")
    if token:
        try:
            payload = decode_jwt_token(token, settings.JWT_SECRET)
        except Exception:
            await websocket.close(code=4001, reason="Invalid token")
            return
    else:
        await websocket.close(code=4001, reason="Token required")
        return

    try:
        from manager.main import app
        redis = getattr(app.state, "redis", None)
        if not redis:
            await websocket.close(code=4002, reason="Redis unavailable")
            return

        pubsub = redis.pubsub()
        await pubsub.subscribe("alerts:live")

        try:
            while True:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if message and message.get("type") == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    await websocket.send_text(data)
                await asyncio.sleep(0.1)
        except WebSocketDisconnect:
            pass
        finally:
            await pubsub.unsubscribe("alerts:live")
            await pubsub.close()
    except Exception as exc:
        logger.error("alerts websocket error", error=str(exc))
        try:
            await websocket.close(code=4003)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert_to_dict(alert: Alert) -> dict:
    """Convert an Alert ORM object to a dict."""
    return {
        "id": str(alert.id),
        "alert_id": alert.alert_id,
        "rule_id": str(alert.rule_id) if alert.rule_id else None,
        "agent_id": str(alert.agent_id) if alert.agent_id else None,
        "severity": alert.severity.value,
        "status": alert.status.value,
        "title": alert.title,
        "description": alert.description,
        "source_ip": str(alert.source_ip) if alert.source_ip else None,
        "destination_ip": str(alert.destination_ip) if alert.destination_ip else None,
        "username": alert.username,
        "raw_log": alert.raw_log,
        "parsed_event": alert.parsed_event,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "mitre_subtechnique": alert.mitre_subtechnique,
        "assignee": str(alert.assignee) if alert.assignee else None,
        "case_id": str(alert.case_id) if alert.case_id else None,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "updated_at": alert.updated_at.isoformat() if alert.updated_at else None,
    }

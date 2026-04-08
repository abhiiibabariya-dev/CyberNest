"""
CyberNest Manager -- Playbooks router.

SOAR playbook management: CRUD, enable/disable toggle, manual trigger,
execution history, and YAML import.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import (
    Alert,
    AuditLog,
    Playbook,
    PlaybookExecStatus,
    PlaybookExecution,
)
from shared.utils.logger import get_logger

logger = get_logger("manager.playbooks")
settings = get_settings()

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class PlaybookCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    trigger_type: str = Field(default="manual")
    trigger_conditions: dict = Field(default_factory=dict)
    content_yaml: str = Field(..., min_length=1)
    is_enabled: bool = True


class PlaybookUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    content_yaml: Optional[str] = None
    is_enabled: Optional[bool] = None


class PlaybookTriggerRequest(BaseModel):
    alert_id: Optional[str] = None
    trigger_context: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@router.get("/")
async def list_playbooks(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    is_enabled: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List playbooks with pagination."""
    query = select(Playbook)
    count_query = select(func.count(Playbook.id))
    conditions = []

    if is_enabled is not None:
        conditions.append(Playbook.is_enabled == is_enabled)
    if search:
        conditions.append(
            Playbook.name.ilike(f"%{search}%") | Playbook.description.ilike(f"%{search}%")
        )

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    query = query.order_by(Playbook.run_count.desc(), Playbook.created_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    playbooks = result.scalars().all()

    return {
        "items": [_playbook_to_dict(p) for p in playbooks],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_playbook(
    body: PlaybookCreateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Create a new playbook."""
    try:
        yaml.safe_load(body.content_yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

    playbook = Playbook(
        name=body.name,
        description=body.description,
        trigger_type=body.trigger_type,
        trigger_conditions=body.trigger_conditions,
        content_yaml=body.content_yaml,
        is_enabled=body.is_enabled,
        created_by=current_user.user_id,
    )
    db.add(playbook)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="create",
        resource_type="playbook",
        resource_id=str(playbook.id),
        details={"name": body.name},
    )
    db.add(audit)

    return _playbook_to_dict(playbook)


@router.get("/{playbook_uuid}")
async def get_playbook(
    playbook_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get playbook detail."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_uuid))
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return _playbook_to_dict(playbook)


@router.put("/{playbook_uuid}")
async def update_playbook(
    playbook_uuid: uuid.UUID,
    body: PlaybookUpdateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Update a playbook."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_uuid))
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")

    changes = {}
    if body.name is not None:
        playbook.name = body.name
        changes["name"] = body.name
    if body.description is not None:
        playbook.description = body.description
        changes["description"] = "updated"
    if body.trigger_type is not None:
        playbook.trigger_type = body.trigger_type
        changes["trigger_type"] = body.trigger_type
    if body.trigger_conditions is not None:
        playbook.trigger_conditions = body.trigger_conditions
        changes["trigger_conditions"] = "updated"
    if body.content_yaml is not None:
        try:
            yaml.safe_load(body.content_yaml)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")
        playbook.content_yaml = body.content_yaml
        changes["content_yaml"] = "updated"
    if body.is_enabled is not None:
        playbook.is_enabled = body.is_enabled
        changes["is_enabled"] = body.is_enabled

    playbook.updated_at = datetime.now(timezone.utc)
    db.add(playbook)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="update",
        resource_type="playbook",
        resource_id=str(playbook_uuid),
        details=changes,
    )
    db.add(audit)

    return _playbook_to_dict(playbook)


@router.delete("/{playbook_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(
    playbook_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Delete a playbook and its execution history."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_uuid))
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")

    await db.delete(playbook)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="delete",
        resource_type="playbook",
        resource_id=str(playbook_uuid),
        details={"name": playbook.name},
    )
    db.add(audit)


@router.post("/{playbook_uuid}/toggle")
async def toggle_playbook(
    playbook_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Toggle playbook enabled/disabled."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_uuid))
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")

    playbook.is_enabled = not playbook.is_enabled
    playbook.updated_at = datetime.now(timezone.utc)
    db.add(playbook)

    return {"id": str(playbook.id), "is_enabled": playbook.is_enabled}


# ---------------------------------------------------------------------------
# Trigger + Execution History
# ---------------------------------------------------------------------------

@router.post("/{playbook_uuid}/trigger")
async def trigger_playbook(
    playbook_uuid: uuid.UUID,
    body: PlaybookTriggerRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger a playbook execution."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_uuid))
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")

    if not playbook.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Playbook is disabled",
        )

    alert_uuid = None
    if body.alert_id:
        try:
            alert_uuid = uuid.UUID(body.alert_id)
            # Verify alert exists
            alert_result = await db.execute(select(Alert).where(Alert.id == alert_uuid))
            if alert_result.scalar_one_or_none() is None:
                raise HTTPException(status_code=404, detail="Alert not found")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid alert UUID")

    execution = PlaybookExecution(
        playbook_id=playbook_uuid,
        alert_id=alert_uuid,
        triggered_by=f"manual:{current_user.username}",
        trigger_context=body.trigger_context,
        status=PlaybookExecStatus.pending,
        steps_log=[],
    )
    db.add(execution)

    playbook.run_count += 1
    db.add(playbook)
    await db.flush()

    # Publish execution to Kafka/Redis for the SOAR engine to pick up
    try:
        from manager.main import app
        redis = getattr(app.state, "redis", None)
        if redis:
            import json
            await redis.publish(
                "playbook:execute",
                json.dumps({
                    "execution_id": str(execution.id),
                    "playbook_id": str(playbook_uuid),
                    "alert_id": str(alert_uuid) if alert_uuid else None,
                    "triggered_by": execution.triggered_by,
                    "trigger_context": body.trigger_context,
                }),
            )
    except Exception as exc:
        logger.warning("failed to publish playbook execution", error=str(exc))

    audit = AuditLog(
        user_id=current_user.user_id,
        action="trigger",
        resource_type="playbook",
        resource_id=str(playbook_uuid),
        details={"execution_id": str(execution.id)},
    )
    db.add(audit)

    return {
        "execution_id": str(execution.id),
        "playbook_id": str(playbook_uuid),
        "status": execution.status.value,
        "detail": "Playbook execution queued",
    }


@router.get("/{playbook_uuid}/executions")
async def list_executions(
    playbook_uuid: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[str] = Query(None, alias="status"),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List execution history for a playbook."""
    query = select(PlaybookExecution).where(PlaybookExecution.playbook_id == playbook_uuid)
    count_query = select(func.count(PlaybookExecution.id)).where(
        PlaybookExecution.playbook_id == playbook_uuid
    )

    if status_filter:
        try:
            st = PlaybookExecStatus(status_filter)
            query = query.where(PlaybookExecution.status == st)
            count_query = count_query.where(PlaybookExecution.status == st)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")

    query = query.order_by(PlaybookExecution.started_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    executions = result.scalars().all()

    return {
        "items": [_execution_to_dict(e) for e in executions],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

@router.post("/import")
async def import_playbook(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Import a playbook from a YAML file."""
    if not file.filename or not file.filename.endswith((".yml", ".yaml")):
        raise HTTPException(status_code=400, detail="File must be YAML (.yml or .yaml)")

    content = await file.read()
    content_str = content.decode("utf-8")

    try:
        data = yaml.safe_load(content_str)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="YAML must contain a mapping")

    name = data.get("name", file.filename or "Imported Playbook")
    description = data.get("description", "")
    trigger_type = data.get("trigger_type", "manual")
    trigger_conditions = data.get("trigger_conditions", {})

    playbook = Playbook(
        name=name[:255],
        description=description,
        trigger_type=trigger_type,
        trigger_conditions=trigger_conditions if isinstance(trigger_conditions, dict) else {},
        content_yaml=content_str,
        is_enabled=True,
        created_by=current_user.user_id,
    )
    db.add(playbook)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="import",
        resource_type="playbook",
        resource_id=str(playbook.id),
        details={"name": name, "filename": file.filename},
    )
    db.add(audit)

    return _playbook_to_dict(playbook)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _playbook_to_dict(p: Playbook) -> dict:
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "trigger_type": p.trigger_type,
        "trigger_conditions": p.trigger_conditions,
        "content_yaml": p.content_yaml,
        "is_enabled": p.is_enabled,
        "run_count": p.run_count,
        "created_by": str(p.created_by) if p.created_by else None,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _execution_to_dict(e: PlaybookExecution) -> dict:
    return {
        "id": str(e.id),
        "playbook_id": str(e.playbook_id),
        "alert_id": str(e.alert_id) if e.alert_id else None,
        "triggered_by": e.triggered_by,
        "trigger_context": e.trigger_context,
        "status": e.status.value,
        "steps_log": e.steps_log,
        "result_summary": e.result_summary,
        "started_at": e.started_at.isoformat() if e.started_at else None,
        "completed_at": e.completed_at.isoformat() if e.completed_at else None,
        "duration_ms": e.duration_ms,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }

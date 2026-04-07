"""CyberNest — Playbook management and execution API routes."""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user, require_analyst, require_soc_lead
from app.core.kafka import publish_event, Topics
from app.models.auth import User
from app.models.soar import Playbook, PlaybookRun
from app.models.enums import PlaybookStatus
from app.schemas.soar import (
    PlaybookCreate, PlaybookResponse, PlaybookTrigger, PlaybookRunResponse,
)

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


@router.get("", response_model=list[PlaybookResponse])
async def list_playbooks(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    enabled: bool | None = None,
    trigger_type: str | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    query = select(Playbook).order_by(desc(Playbook.created_at)).limit(limit).offset(offset)
    if enabled is not None:
        query = query.where(Playbook.enabled == enabled)
    if trigger_type:
        query = query.where(Playbook.trigger_type == trigger_type)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=PlaybookResponse, status_code=201)
async def create_playbook(
    data: PlaybookCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_soc_lead)],
):
    playbook = Playbook(
        name=data.name,
        description=data.description,
        trigger_type=data.trigger_type,
        trigger_conditions=data.trigger_conditions,
        steps=data.steps,
        yaml_definition=data.yaml_definition,
        author=current_user.full_name,
        tags=data.tags,
    )
    db.add(playbook)
    await db.flush()
    await db.refresh(playbook)
    return playbook


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


@router.post("/trigger", response_model=PlaybookRunResponse, status_code=202)
async def trigger_playbook(
    data: PlaybookTrigger,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
):
    """Trigger playbook execution — dispatches to SOAR service via Kafka."""
    result = await db.execute(select(Playbook).where(Playbook.id == data.playbook_id))
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if not playbook.enabled:
        raise HTTPException(status_code=400, detail="Playbook is disabled")

    # Create run record
    run = PlaybookRun(
        playbook_id=playbook.id,
        incident_id=data.incident_id,
        alert_id=data.alert_id,
        triggered_by=current_user.id,
        status=PlaybookStatus.PENDING,
        is_dry_run=data.dry_run,
        input_data=data.input_data,
    )
    db.add(run)
    await db.flush()
    await db.refresh(run)

    # Dispatch to SOAR engine via Kafka
    await publish_event(Topics.SOAR_ACTIONS, {
        "run_id": str(run.id),
        "playbook_id": str(playbook.id),
        "playbook_name": playbook.name,
        "steps": playbook.steps,
        "input_data": data.input_data,
        "alert_id": str(data.alert_id) if data.alert_id else None,
        "incident_id": str(data.incident_id) if data.incident_id else None,
        "dry_run": data.dry_run,
        "triggered_by": current_user.full_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return run


@router.get("/runs", response_model=list[PlaybookRunResponse])
async def list_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    playbook_id: uuid.UUID | None = None,
    status: PlaybookStatus | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    query = select(PlaybookRun).order_by(desc(PlaybookRun.started_at)).limit(limit).offset(offset)
    if playbook_id:
        query = query.where(PlaybookRun.playbook_id == playbook_id)
    if status:
        query = query.where(PlaybookRun.status == status)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/runs/{run_id}", response_model=PlaybookRunResponse)
async def get_run(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(PlaybookRun).where(PlaybookRun.id == run_id))
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    return run

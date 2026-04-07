"""CyberNest — Detection rule management API routes."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user, require_analyst, require_soc_lead
from app.models.auth import User
from app.models.siem import DetectionRule
from app.models.enums import Severity
from app.schemas.siem import RuleCreate, RuleResponse, RuleUpdate

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


@router.get("", response_model=list[RuleResponse])
async def list_rules(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    severity: Severity | None = None,
    enabled: bool | None = None,
    group: str | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
):
    query = select(DetectionRule).order_by(desc(DetectionRule.total_hits)).limit(limit).offset(offset)
    if severity:
        query = query.where(DetectionRule.severity == severity)
    if enabled is not None:
        query = query.where(DetectionRule.enabled == enabled)
    if group:
        query = query.where(DetectionRule.group == group)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=RuleResponse, status_code=201)
async def create_rule(
    data: RuleCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_soc_lead)],
):
    # Check uniqueness
    existing = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == data.rule_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Rule ID {data.rule_id} already exists")

    rule = DetectionRule(
        rule_id=data.rule_id,
        name=data.name,
        description=data.description,
        severity=data.severity,
        level=data.level,
        rule_type=data.rule_type,
        logic=data.logic,
        sigma_yaml=data.sigma_yaml,
        mitre_tactics=data.mitre_tactics,
        mitre_techniques=data.mitre_techniques,
        group=data.group,
        tags=data.tags,
        author=data.author or current_user.full_name,
        false_positive_notes=data.false_positive_notes,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    data: RuleUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_soc_lead)],
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(rule, field, value)

    rule.version += 1
    await db.flush()
    await db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)


@router.post("/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_soc_lead)],
):
    result = await db.execute(select(DetectionRule).where(DetectionRule.rule_id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = not rule.enabled
    await db.flush()
    return {"rule_id": rule_id, "enabled": rule.enabled}

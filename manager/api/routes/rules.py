"""
CyberNest Manager -- Rules router.

Full detection rule management: CRUD, enable/disable toggle, Sigma YAML import,
rule testing against sample JSON, and hit count statistics.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import AuditLog, Rule
from shared.utils.logger import get_logger

logger = get_logger("manager.rules")
settings = get_settings()

router = APIRouter(prefix="/rules", tags=["Rules"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RuleCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    level: int = Field(..., ge=1, le=5)
    category: Optional[str] = Field(None, max_length=100)
    mitre_tactic: Optional[str] = Field(None, max_length=100)
    mitre_technique: list[str] = Field(default_factory=list)
    content_yaml: str = Field(..., min_length=1)
    sigma_id: Optional[str] = Field(None, max_length=64)
    is_enabled: bool = True


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    level: Optional[int] = Field(None, ge=1, le=5)
    category: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[list[str]] = None
    content_yaml: Optional[str] = None
    is_enabled: Optional[bool] = None


class RuleTestRequest(BaseModel):
    rule_content_yaml: str = Field(..., description="Sigma/YAML rule content to test")
    sample_event: dict = Field(..., description="Sample JSON event to test against")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
async def list_rules(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    category: Optional[str] = None,
    level: Optional[int] = None,
    is_enabled: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List rules with filters and hit_count."""
    query = select(Rule)
    count_query = select(func.count(Rule.id))
    conditions = []

    if category:
        conditions.append(Rule.category == category)
    if level is not None:
        conditions.append(Rule.level == level)
    if is_enabled is not None:
        conditions.append(Rule.is_enabled == is_enabled)
    if search:
        conditions.append(
            Rule.name.ilike(f"%{search}%") | Rule.description.ilike(f"%{search}%")
        )

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    query = query.order_by(Rule.hit_count.desc(), Rule.created_at.desc())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    rules = result.scalars().all()

    return {
        "items": [_rule_to_dict(r) for r in rules],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Create a new detection rule from YAML content."""
    # Validate YAML
    try:
        yaml.safe_load(body.content_yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

    rule_id_str = f"rule-{uuid.uuid4().hex[:12]}"

    rule = Rule(
        rule_id=rule_id_str,
        name=body.name,
        description=body.description,
        level=body.level,
        category=body.category,
        mitre_tactic=body.mitre_tactic,
        mitre_technique=body.mitre_technique,
        content_yaml=body.content_yaml,
        sigma_id=body.sigma_id,
        is_enabled=body.is_enabled,
        created_by=current_user.user_id,
    )
    db.add(rule)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="create",
        resource_type="rule",
        resource_id=str(rule.id),
        details={"name": body.name, "level": body.level},
    )
    db.add(audit)

    logger.info("rule created", rule_id=rule_id_str, name=body.name)
    return _rule_to_dict(rule)


@router.get("/stats")
async def rule_stats(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get top 20 rules by hit count."""
    result = await db.execute(
        select(Rule)
        .where(Rule.hit_count > 0)
        .order_by(Rule.hit_count.desc())
        .limit(20)
    )
    rules = result.scalars().all()

    total_result = await db.execute(select(func.count(Rule.id)))
    total_rules = total_result.scalar() or 0

    enabled_result = await db.execute(
        select(func.count(Rule.id)).where(Rule.is_enabled == True)
    )
    enabled_rules = enabled_result.scalar() or 0

    return {
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "disabled_rules": total_rules - enabled_rules,
        "top_rules": [
            {
                "id": str(r.id),
                "rule_id": r.rule_id,
                "name": r.name,
                "level": r.level,
                "hit_count": r.hit_count,
                "false_positive_count": r.false_positive_count,
            }
            for r in rules
        ],
    }


@router.get("/{rule_uuid}")
async def get_rule(
    rule_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get rule detail."""
    result = await db.execute(select(Rule).where(Rule.id == rule_uuid))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _rule_to_dict(rule)


@router.put("/{rule_uuid}")
async def update_rule(
    rule_uuid: uuid.UUID,
    body: RuleUpdateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Update an existing rule."""
    result = await db.execute(select(Rule).where(Rule.id == rule_uuid))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    changes = {}
    if body.name is not None:
        rule.name = body.name
        changes["name"] = body.name
    if body.description is not None:
        rule.description = body.description
        changes["description"] = "updated"
    if body.level is not None:
        rule.level = body.level
        changes["level"] = body.level
    if body.category is not None:
        rule.category = body.category
        changes["category"] = body.category
    if body.mitre_tactic is not None:
        rule.mitre_tactic = body.mitre_tactic
        changes["mitre_tactic"] = body.mitre_tactic
    if body.mitre_technique is not None:
        rule.mitre_technique = body.mitre_technique
        changes["mitre_technique"] = body.mitre_technique
    if body.content_yaml is not None:
        try:
            yaml.safe_load(body.content_yaml)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")
        rule.content_yaml = body.content_yaml
        changes["content_yaml"] = "updated"
    if body.is_enabled is not None:
        rule.is_enabled = body.is_enabled
        changes["is_enabled"] = body.is_enabled

    rule.updated_at = datetime.now(timezone.utc)
    db.add(rule)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="update",
        resource_type="rule",
        resource_id=str(rule_uuid),
        details=changes,
    )
    db.add(audit)

    return _rule_to_dict(rule)


@router.delete("/{rule_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Delete a rule."""
    result = await db.execute(select(Rule).where(Rule.id == rule_uuid))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    await db.delete(rule)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="delete",
        resource_type="rule",
        resource_id=str(rule_uuid),
        details={"name": rule.name},
    )
    db.add(audit)

    logger.info("rule deleted", rule_id=rule.rule_id, name=rule.name)


@router.post("/{rule_uuid}/toggle")
async def toggle_rule(
    rule_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Toggle rule enabled/disabled."""
    result = await db.execute(select(Rule).where(Rule.id == rule_uuid))
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")

    rule.is_enabled = not rule.is_enabled
    rule.updated_at = datetime.now(timezone.utc)
    db.add(rule)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="toggle",
        resource_type="rule",
        resource_id=str(rule_uuid),
        details={"is_enabled": rule.is_enabled},
    )
    db.add(audit)

    return {"id": str(rule.id), "is_enabled": rule.is_enabled}


@router.post("/import/sigma")
async def import_sigma_rule(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead", "analyst")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Upload a Sigma YAML file, parse it, and store as a rule."""
    if not file.filename or not file.filename.endswith((".yml", ".yaml")):
        raise HTTPException(status_code=400, detail="File must be a YAML file (.yml or .yaml)")

    content = await file.read()
    content_str = content.decode("utf-8")

    try:
        sigma_data = yaml.safe_load(content_str)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

    if not isinstance(sigma_data, dict):
        raise HTTPException(status_code=400, detail="YAML must contain a mapping")

    # Extract Sigma fields
    title = sigma_data.get("title", file.filename or "Imported Sigma Rule")
    description = sigma_data.get("description", "")
    sigma_id = sigma_data.get("id", "")

    # Map Sigma level to our 1-5 scale
    level_map = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    sigma_level = sigma_data.get("level", "medium")
    level = level_map.get(sigma_level, 3)

    # Extract MITRE ATT&CK tags
    tags = sigma_data.get("tags", [])
    mitre_techniques = []
    mitre_tactic = None
    for tag in tags:
        if isinstance(tag, str):
            if tag.startswith("attack.t"):
                mitre_techniques.append(tag.replace("attack.", "").upper())
            elif tag.startswith("attack."):
                mitre_tactic = tag.replace("attack.", "")

    rule_id_str = f"sigma-{uuid.uuid4().hex[:12]}"

    # Check for duplicate sigma_id
    if sigma_id:
        existing = await db.execute(select(Rule).where(Rule.sigma_id == sigma_id))
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Sigma rule with ID {sigma_id} already exists",
            )

    rule = Rule(
        rule_id=rule_id_str,
        name=title[:255],
        description=description,
        level=level,
        category=sigma_data.get("logsource", {}).get("category"),
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_techniques,
        content_yaml=content_str,
        sigma_id=sigma_id or None,
        is_enabled=True,
        created_by=current_user.user_id,
    )
    db.add(rule)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="import_sigma",
        resource_type="rule",
        resource_id=str(rule.id),
        details={"sigma_id": sigma_id, "title": title},
    )
    db.add(audit)

    logger.info("sigma rule imported", rule_id=rule_id_str, sigma_id=sigma_id)
    return _rule_to_dict(rule)


@router.post("/test")
async def test_rule(
    body: RuleTestRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Test a rule against a sample JSON event.

    Performs basic keyword/field matching from the Sigma detection block.
    This is a simplified matcher for quick rule validation.
    """
    try:
        sigma_data = yaml.safe_load(body.rule_content_yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")

    if not isinstance(sigma_data, dict):
        raise HTTPException(status_code=400, detail="YAML must contain a mapping")

    detection = sigma_data.get("detection", {})
    if not detection:
        return {
            "matched": False,
            "reason": "No detection block in rule",
            "details": {},
        }

    # Simple field matcher
    event = body.sample_event
    event_str = json.dumps(event).lower()
    matches = []
    misses = []

    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            for field, pattern in value.items():
                field_clean = field.rstrip("|contains|endswith|startswith|all|re")
                event_value = _get_nested_value(event, field_clean)

                if isinstance(pattern, list):
                    patterns = pattern
                else:
                    patterns = [pattern]

                field_matched = False
                for p in patterns:
                    p_str = str(p).lower()
                    if "|contains" in field:
                        if event_value and p_str in str(event_value).lower():
                            field_matched = True
                    elif "|endswith" in field:
                        if event_value and str(event_value).lower().endswith(p_str):
                            field_matched = True
                    elif "|startswith" in field:
                        if event_value and str(event_value).lower().startswith(p_str):
                            field_matched = True
                    elif "|re" in field:
                        try:
                            if event_value and re.search(p_str, str(event_value).lower()):
                                field_matched = True
                        except re.error:
                            pass
                    else:
                        if event_value is not None and str(event_value).lower() == p_str:
                            field_matched = True

                if field_matched:
                    matches.append(f"{field} matched")
                else:
                    misses.append(f"{field} did not match (expected: {pattern})")
        elif isinstance(value, list):
            for keyword in value:
                if str(keyword).lower() in event_str:
                    matches.append(f"keyword '{keyword}' found")
                else:
                    misses.append(f"keyword '{keyword}' not found")

    matched = len(matches) > 0 and len(misses) == 0

    return {
        "matched": matched,
        "matches": matches,
        "misses": misses,
        "details": {
            "rule_title": sigma_data.get("title", ""),
            "rule_level": sigma_data.get("level", ""),
        },
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_nested_value(obj: dict, key: str) -> Any:
    """Get a nested value from a dict using dot notation."""
    parts = key.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _rule_to_dict(rule: Rule) -> dict:
    return {
        "id": str(rule.id),
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "level": rule.level,
        "category": rule.category,
        "mitre_tactic": rule.mitre_tactic,
        "mitre_technique": rule.mitre_technique or [],
        "content_yaml": rule.content_yaml,
        "sigma_id": rule.sigma_id,
        "is_enabled": rule.is_enabled,
        "hit_count": rule.hit_count,
        "false_positive_count": rule.false_positive_count,
        "created_by": str(rule.created_by) if rule.created_by else None,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }

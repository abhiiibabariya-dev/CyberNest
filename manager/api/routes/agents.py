"""
CyberNest Manager -- Agents router.

Full agent fleet management: registration, listing, detail, config updates,
deactivation, remote commands via Redis pub/sub, and event retrieval from ES.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user, require_role
from manager.config import get_settings
from manager.db.database import get_db
from manager.db.models import Agent, AgentStatusEnum, AuditLog
from shared.utils.crypto import generate_api_key, hash_api_key
from shared.utils.logger import get_logger

logger = get_logger("manager.agents")
settings = get_settings()

router = APIRouter(prefix="/agents", tags=["Agents"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AgentRegisterRequest(BaseModel):
    hostname: str = Field(..., max_length=255)
    ip: str = Field(..., max_length=45)
    os: str = Field(..., max_length=50)
    os_version: Optional[str] = Field(None, max_length=100)
    architecture: Optional[str] = Field(None, max_length=20)
    version: str = Field(..., max_length=20)
    tags: list[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)


class AgentUpdateRequest(BaseModel):
    config_json: Optional[dict] = None
    tags: Optional[list[str]] = None
    hostname: Optional[str] = None


class AgentCommandRequest(BaseModel):
    command: str = Field(..., description="Command: isolate, restart, update, collect_forensics, run_scan")
    parameters: dict = Field(default_factory=dict)
    timeout: int = Field(default=60, ge=1, le=3600)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_agent(
    body: AgentRegisterRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Register a new agent. Generates an API key and returns an enrollment token."""
    api_key = generate_api_key()
    api_key_hashed = hash_api_key(api_key)
    agent_id_str = f"agent-{uuid.uuid4().hex[:16]}"

    agent = Agent(
        agent_id=agent_id_str,
        hostname=body.hostname,
        ip=body.ip,
        os=body.os,
        os_version=body.os_version,
        architecture=body.architecture,
        version=body.version,
        status=AgentStatusEnum.offline,
        api_key_hash=api_key_hashed,
        config_json=body.config,
        tags=body.tags,
    )
    db.add(agent)
    await db.flush()

    audit = AuditLog(
        user_id=current_user.user_id,
        action="register",
        resource_type="agent",
        resource_id=str(agent.id),
        details={"hostname": body.hostname, "ip": body.ip},
    )
    db.add(audit)

    logger.info("agent registered", agent_id=agent_id_str, hostname=body.hostname)

    return {
        "id": str(agent.id),
        "agent_id": agent_id_str,
        "api_key": api_key,
        "enrollment_token": api_key,
        "manager_url": f"wss://{settings.API_HOST}:{settings.AGENT_TLS_PORT}",
        "detail": "Agent registered. Store the API key securely -- it will not be shown again.",
    }


@router.get("/")
async def list_agents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status_filter: Optional[str] = Query(None, alias="status"),
    hostname: Optional[str] = None,
    tag: Optional[str] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all agents with status and pagination."""
    query = select(Agent)
    count_query = select(func.count(Agent.id))
    conditions = []

    if status_filter:
        try:
            st = AgentStatusEnum(status_filter)
            conditions.append(Agent.status == st)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status_filter}")

    if hostname:
        conditions.append(Agent.hostname.ilike(f"%{hostname}%"))

    if tag:
        conditions.append(Agent.tags.any(tag))

    if conditions:
        query = query.where(and_(*conditions))
        count_query = count_query.where(and_(*conditions))

    query = query.order_by(Agent.last_seen.desc().nullslast())
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(query)
    agents = result.scalars().all()

    return {
        "items": [_agent_to_dict(a) for a in agents],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.get("/{agent_uuid}")
async def get_agent(
    agent_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get agent detail with recent event count from ES."""
    result = await db.execute(select(Agent).where(Agent.id == agent_uuid))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    data = _agent_to_dict(agent)

    # Try to get recent event count from ES
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
        if es:
            es_result = await es.count(
                index=settings.ES_INDEX_EVENTS,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"agent.id": agent.agent_id}},
                                {"range": {"@timestamp": {"gte": "now-24h"}}},
                            ]
                        }
                    }
                },
            )
            data["events_24h"] = es_result.get("count", 0)
    except Exception:
        data["events_24h"] = 0

    return data


@router.patch("/{agent_uuid}")
async def update_agent(
    agent_uuid: uuid.UUID,
    body: AgentUpdateRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Update agent configuration and/or tags."""
    result = await db.execute(select(Agent).where(Agent.id == agent_uuid))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    changes = {}
    if body.config_json is not None:
        agent.config_json = body.config_json
        changes["config_json"] = "updated"
    if body.tags is not None:
        agent.tags = body.tags
        changes["tags"] = body.tags
    if body.hostname is not None:
        agent.hostname = body.hostname
        changes["hostname"] = body.hostname

    agent.updated_at = datetime.now(timezone.utc)
    db.add(agent)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="update",
        resource_type="agent",
        resource_id=str(agent_uuid),
        details=changes,
    )
    db.add(audit)

    return _agent_to_dict(agent)


@router.delete("/{agent_uuid}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_agent(
    agent_uuid: uuid.UUID,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate an agent (set status to offline, not hard delete)."""
    result = await db.execute(select(Agent).where(Agent.id == agent_uuid))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent.status = AgentStatusEnum.offline
    agent.updated_at = datetime.now(timezone.utc)
    db.add(agent)

    audit = AuditLog(
        user_id=current_user.user_id,
        action="deactivate",
        resource_type="agent",
        resource_id=str(agent_uuid),
    )
    db.add(audit)

    logger.info("agent deactivated", agent_id=agent.agent_id)


@router.post("/{agent_uuid}/command")
async def send_agent_command(
    agent_uuid: uuid.UUID,
    body: AgentCommandRequest,
    current_user: AuthenticatedUser = Depends(
        require_role("super_admin", "admin", "soc_lead")
    ),
    db: AsyncSession = Depends(get_db),
):
    """Push a command to an agent via Redis pub/sub."""
    result = await db.execute(select(Agent).where(Agent.id == agent_uuid))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if agent.status == AgentStatusEnum.offline:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Agent is offline. Command will not be delivered.",
        )

    command_payload = {
        "agent_id": agent.agent_id,
        "command": body.command,
        "parameters": body.parameters,
        "timeout": body.timeout,
        "issued_by": current_user.username,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        from manager.main import app
        redis = getattr(app.state, "redis", None)
        if redis:
            await redis.publish(
                f"agent:command:{agent.agent_id}",
                json.dumps(command_payload),
            )
    except Exception as exc:
        logger.error("failed to publish agent command", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to dispatch command",
        )

    audit = AuditLog(
        user_id=current_user.user_id,
        action="send_command",
        resource_type="agent",
        resource_id=str(agent_uuid),
        details=command_payload,
    )
    db.add(audit)

    logger.info(
        "command sent to agent",
        agent_id=agent.agent_id,
        command=body.command,
    )

    return {
        "detail": "Command dispatched",
        "agent_id": agent.agent_id,
        "command": body.command,
    }


@router.get("/{agent_uuid}/events")
async def get_agent_events(
    agent_uuid: uuid.UUID,
    limit: int = Query(100, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get recent events for an agent from Elasticsearch."""
    result = await db.execute(select(Agent).where(Agent.id == agent_uuid))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    events = []
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
        if es:
            es_result = await es.search(
                index=settings.ES_INDEX_EVENTS,
                body={
                    "query": {
                        "term": {"agent.id": agent.agent_id}
                    },
                    "size": limit,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                },
            )
            events = [
                hit["_source"] for hit in es_result.get("hits", {}).get("hits", [])
            ]
    except Exception as exc:
        logger.warning("failed to fetch agent events from ES", error=str(exc))

    return {
        "agent_id": agent.agent_id,
        "events": events,
        "count": len(events),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_to_dict(agent: Agent) -> dict:
    return {
        "id": str(agent.id),
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "ip": str(agent.ip) if agent.ip else None,
        "os": agent.os,
        "os_version": agent.os_version,
        "architecture": agent.architecture,
        "version": agent.version,
        "status": agent.status.value,
        "enrolled_at": agent.enrolled_at.isoformat() if agent.enrolled_at else None,
        "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        "config_json": agent.config_json,
        "tags": agent.tags or [],
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "updated_at": agent.updated_at.isoformat() if agent.updated_at else None,
    }

"""CyberNest — Agent management API routes."""

import secrets
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user, require_admin, require_analyst
from app.core.kafka import publish_event, Topics
from app.core.redis import redis_client
from app.models.auth import User
from app.models.siem import Agent
from app.models.enums import AgentStatus
from app.schemas.siem import AgentRegister, AgentResponse, AgentHeartbeat

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.post("/register", response_model=AgentResponse, status_code=201)
async def register_agent(data: AgentRegister, db: Annotated[AsyncSession, Depends(get_db)]):
    auth_key = secrets.token_hex(32)
    agent = Agent(
        hostname=data.hostname,
        ip_address=data.ip_address,
        os_type=data.os_type,
        os_version=data.os_version,
        agent_version=data.agent_version,
        auth_key=auth_key,
        status=AgentStatus.ONLINE,
        labels=data.labels,
        group=data.group,
        last_seen=datetime.now(timezone.utc),
        last_heartbeat=datetime.now(timezone.utc),
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)

    # Cache agent status in Redis
    await redis_client.hset(f"agent:{agent.id}", mapping={
        "status": "online",
        "hostname": agent.hostname,
        "last_seen": datetime.now(timezone.utc).isoformat(),
    })
    await redis_client.expire(f"agent:{agent.id}", 120)  # 2 min TTL

    return agent


@router.get("", response_model=list[AgentResponse])
async def list_agents(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    status: AgentStatus | None = None,
    group: str | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
):
    query = select(Agent).order_by(Agent.last_seen.desc()).limit(limit).offset(offset)
    if status:
        query = query.where(Agent.status == status)
    if group:
        query = query.where(Agent.group == group)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/{agent_id}/status")
async def get_agent_status(agent_id: uuid.UUID):
    cached = await redis_client.hgetall(f"agent:{agent_id}")
    if cached:
        return cached
    return {"status": "unknown", "detail": "No heartbeat data"}


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: uuid.UUID,
    data: AgentHeartbeat,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    now = datetime.now(timezone.utc)
    agent.last_heartbeat = now
    agent.last_seen = now
    agent.status = AgentStatus.ONLINE
    agent.cpu_usage = data.cpu_usage
    agent.memory_usage = data.memory_usage
    agent.events_per_second = data.events_per_second
    await db.flush()

    # Update Redis cache
    await redis_client.hset(f"agent:{agent_id}", mapping={
        "status": "online",
        "hostname": agent.hostname,
        "last_seen": now.isoformat(),
        "cpu": str(data.cpu_usage or 0),
        "memory": str(data.memory_usage or 0),
        "eps": str(data.events_per_second or 0),
    })
    await redis_client.expire(f"agent:{agent_id}", 120)

    # Publish heartbeat to Kafka
    await publish_event(Topics.AGENT_HEARTBEAT, {
        "agent_id": str(agent_id),
        "hostname": agent.hostname,
        "timestamp": now.isoformat(),
        "cpu_usage": data.cpu_usage,
        "memory_usage": data.memory_usage,
        "eps": data.events_per_second,
    })

    return {"status": "ok"}


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_admin)],
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.delete(agent)
    await redis_client.delete(f"agent:{agent_id}")

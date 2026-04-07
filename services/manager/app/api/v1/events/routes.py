"""CyberNest — Event ingestion and log search API routes."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import get_current_user, require_analyst
from app.core.kafka import publish_event, Topics
from app.core.elasticsearch import es_client
from app.models.auth import User
from app.schemas.siem import (
    LogIngest, LogIngestBatch, LogIngestResponse,
    SearchQuery, SearchResponse,
)

router = APIRouter(prefix="/events", tags=["Events & Logs"])

# Map source type to Kafka topic
SOURCE_TOPIC_MAP = {
    "windows": Topics.RAW_WINDOWS,
    "linux": Topics.RAW_LINUX,
    "network": Topics.RAW_NETWORK,
    "cloud": Topics.RAW_CLOUD,
    "application": Topics.RAW_APPLICATION,
    "syslog": Topics.RAW_SYSLOG,
}


@router.post("/ingest", response_model=LogIngestResponse)
async def ingest_log(data: LogIngest):
    """Ingest a single log event — routes to Kafka by source type."""
    topic = SOURCE_TOPIC_MAP.get(data.source_type or "syslog", Topics.RAW_SYSLOG)
    try:
        await publish_event(topic, {
            "raw": data.raw,
            "source": data.source,
            "source_type": data.source_type,
            "agent_id": str(data.agent_id) if data.agent_id else None,
            "tags": data.tags,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }, key=data.source)
        return LogIngestResponse(accepted=1, rejected=0)
    except Exception as e:
        return LogIngestResponse(accepted=0, rejected=1, errors=[str(e)])


@router.post("/ingest/batch", response_model=LogIngestResponse)
async def ingest_batch(data: LogIngestBatch):
    """Ingest multiple logs in a single request."""
    accepted = 0
    rejected = 0
    errors = []

    for log in data.logs:
        topic = SOURCE_TOPIC_MAP.get(log.source_type or "syslog", Topics.RAW_SYSLOG)
        try:
            await publish_event(topic, {
                "raw": log.raw,
                "source": log.source,
                "source_type": log.source_type,
                "agent_id": str(log.agent_id) if log.agent_id else None,
                "tags": log.tags,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }, key=log.source)
            accepted += 1
        except Exception as e:
            rejected += 1
            errors.append(str(e))

    return LogIngestResponse(accepted=accepted, rejected=rejected, errors=errors if errors else None)


@router.post("/search", response_model=SearchResponse)
async def search_events(
    query: SearchQuery,
    current_user: Annotated[User, Depends(get_current_user)],
):
    """Full-text search over indexed events in Elasticsearch."""
    body: dict = {
        "size": query.size,
        "from": query.offset,
        "sort": [{query.sort_field: {"order": query.sort_order}}],
    }

    # Build query
    must_clauses = []

    if query.q:
        must_clauses.append({
            "query_string": {
                "query": query.q,
                "default_operator": "AND",
                "analyze_wildcard": True,
            }
        })

    if query.from_time or query.to_time:
        range_clause: dict = {"@timestamp": {}}
        if query.from_time:
            range_clause["@timestamp"]["gte"] = query.from_time
        if query.to_time:
            range_clause["@timestamp"]["lte"] = query.to_time
        must_clauses.append({"range": range_clause})

    if query.filters:
        for field, value in query.filters.items():
            must_clauses.append({"match": {field: value}})

    body["query"] = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

    try:
        resp = await es_client.search(index=query.index, body=body)
        return SearchResponse(
            total=resp["hits"]["total"]["value"],
            took_ms=resp["took"],
            hits=[hit["_source"] for hit in resp["hits"]["hits"]],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/search")
async def search_events_get(
    current_user: Annotated[User, Depends(get_current_user)],
    q: str = "",
    index: str = "cybernest-events-*",
    from_time: str | None = Query(None, alias="from"),
    to_time: str | None = Query(None, alias="to"),
    size: int = Query(100, le=10000),
    offset: int = 0,
):
    """GET-based search for convenience (Splunk-like URL search)."""
    query = SearchQuery(
        q=q, index=index, from_time=from_time, to_time=to_time,
        size=size, offset=offset,
    )
    return await search_events(query, current_user)

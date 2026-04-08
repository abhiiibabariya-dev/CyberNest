"""
CyberNest Manager -- Elasticsearch search router.

Supports Lucene query syntax, time range filtering, index selection,
highlighting, and pagination for full-text event search.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from manager.api.middleware.auth_middleware import AuthenticatedUser, get_current_user
from manager.config import get_settings
from shared.utils.logger import get_logger

logger = get_logger("manager.search")
settings = get_settings()

router = APIRouter(prefix="/search", tags=["Search"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=4096, description="Lucene query string")
    index: str = Field(default="cybernest-events-*", description="ES index pattern")
    time_from: Optional[str] = Field(None, description="Start time (ISO 8601 or ES relative like 'now-24h')")
    time_to: Optional[str] = Field(None, description="End time (ISO 8601 or ES relative like 'now')")
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    sort_field: str = Field(default="@timestamp", description="Field to sort by")
    sort_order: str = Field(default="desc", description="asc or desc")
    highlight_fields: list[str] = Field(
        default_factory=lambda: ["message", "raw", "source.ip", "destination.ip", "user.name"],
        description="Fields to highlight in results",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/")
async def search_events(
    body: SearchRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Search Elasticsearch with Lucene query, time range, and highlighting."""
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
    except Exception:
        es = None

    if not es:
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch is not available",
        )

    # Build the ES query
    must_clauses = [
        {
            "query_string": {
                "query": body.query,
                "default_operator": "AND",
                "allow_leading_wildcard": False,
                "analyze_wildcard": True,
            }
        }
    ]

    # Time range filter
    if body.time_from or body.time_to:
        time_range = {}
        if body.time_from:
            time_range["gte"] = body.time_from
        if body.time_to:
            time_range["lte"] = body.time_to
        must_clauses.append({"range": {"@timestamp": time_range}})

    es_body = {
        "query": {
            "bool": {
                "must": must_clauses,
            }
        },
        "from": (body.page - 1) * body.page_size,
        "size": body.page_size,
        "sort": [{body.sort_field: {"order": body.sort_order}}],
        "highlight": {
            "fields": {field: {} for field in body.highlight_fields},
            "pre_tags": ["<mark>"],
            "post_tags": ["</mark>"],
            "fragment_size": 200,
            "number_of_fragments": 3,
        },
        "track_total_hits": True,
    }

    try:
        result = await es.search(index=body.index, body=es_body)
    except Exception as exc:
        error_msg = str(exc)
        logger.error("ES search failed", error=error_msg, query=body.query)
        raise HTTPException(
            status_code=400,
            detail=f"Search failed: {error_msg}",
        )

    hits = result.get("hits", {})
    total_raw = hits.get("total", {})
    if isinstance(total_raw, dict):
        total = total_raw.get("value", 0)
    else:
        total = total_raw

    items = []
    for hit in hits.get("hits", []):
        item = {
            "_index": hit.get("_index"),
            "_id": hit.get("_id"),
            "_score": hit.get("_score"),
            "_source": hit.get("_source", {}),
        }
        if "highlight" in hit:
            item["highlight"] = hit["highlight"]
        items.append(item)

    return {
        "items": items,
        "total": total,
        "page": body.page,
        "page_size": body.page_size,
        "pages": (total + body.page_size - 1) // body.page_size if total else 0,
        "took_ms": result.get("took", 0),
    }


@router.get("/indices")
async def list_indices(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List available Elasticsearch indices matching CyberNest patterns."""
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
    except Exception:
        es = None

    if not es:
        raise HTTPException(status_code=503, detail="Elasticsearch is not available")

    try:
        result = await es.cat.indices(index="cybernest-*", format="json", h="index,docs.count,store.size,creation.date.string")
        indices = []
        for idx in result:
            indices.append({
                "index": idx.get("index"),
                "docs_count": idx.get("docs.count"),
                "store_size": idx.get("store.size"),
                "created": idx.get("creation.date.string"),
            })
        return {"indices": sorted(indices, key=lambda x: x["index"])}
    except Exception as exc:
        logger.error("failed to list indices", error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to list indices")


@router.get("/fields")
async def get_field_mappings(
    index: str = Query(default="cybernest-events-*"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get field mappings for an index to power search autocomplete."""
    try:
        from manager.main import app
        es = getattr(app.state, "es", None)
    except Exception:
        es = None

    if not es:
        raise HTTPException(status_code=503, detail="Elasticsearch is not available")

    try:
        result = await es.indices.get_field_mapping(index=index, fields="*")
        fields = set()
        for idx_name, idx_data in result.items():
            mappings = idx_data.get("mappings", {})
            for field_name in mappings:
                fields.add(field_name)
        return {"fields": sorted(fields)}
    except Exception as exc:
        logger.error("failed to get field mappings", error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to get field mappings")

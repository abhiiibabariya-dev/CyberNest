"""CyberNest Manager — Elasticsearch async client for search and indexing."""

from elasticsearch import AsyncElasticsearch
import structlog

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

es_client = AsyncElasticsearch(
    hosts=[settings.ELASTICSEARCH_URL],
    request_timeout=30,
    max_retries=3,
    retry_on_timeout=True,
)


async def get_es() -> AsyncElasticsearch:
    return es_client


async def close_es():
    await es_client.close()
    logger.info("Elasticsearch client closed")

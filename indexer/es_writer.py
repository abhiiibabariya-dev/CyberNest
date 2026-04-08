"""
CyberNest Indexer Service — Elasticsearch Writer.

Consumes parsed events and alerts from Kafka, buffers them, and bulk-indexes
into date-partitioned Elasticsearch indices with automatic template and ILM
policy provisioning on startup.

Run: python -m indexer.es_writer
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from aiokafka import AIOKafkaConsumer
from aiokafka.errors import KafkaConnectionError, KafkaError, NodeNotReadyError
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk, BulkIndexError
from pydantic_settings import BaseSettings

from shared.utils.logger import get_logger

logger = get_logger("indexer")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class IndexerSettings(BaseSettings):
    """Indexer configuration loaded from environment variables."""

    kafka_bootstrap: str = "localhost:9092"
    kafka_group_id: str = "indexer-group"
    kafka_auto_offset_reset: str = "latest"
    kafka_max_poll_records: int = 500

    es_hosts: str = "http://localhost:9200"
    es_username: str = ""
    es_password: str = ""
    es_api_key: str = ""
    es_verify_certs: bool = False
    es_request_timeout: int = 60

    buffer_max_size: int = 500
    buffer_flush_interval: float = 5.0

    max_retries: int = 3
    retry_backoff_base: float = 1.0

    events_topic: str = "cybernest.parsed.events"
    alerts_topic: str = "cybernest.alerts"

    model_config = {"env_prefix": "INDEXER_", "extra": "ignore"}


settings = IndexerSettings()

# ---------------------------------------------------------------------------
# Path helpers for JSON templates
# ---------------------------------------------------------------------------

TEMPLATES_DIR = Path(__file__).parent / "index_templates"
ILM_DIR = Path(__file__).parent / "ilm_policies"


def _load_json(path: Path) -> dict[str, Any]:
    """Load a JSON file from disk."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Elasticsearch client factory
# ---------------------------------------------------------------------------

def create_es_client() -> AsyncElasticsearch:
    """Create an async Elasticsearch client from settings."""
    hosts = [h.strip() for h in settings.es_hosts.split(",")]
    kwargs: dict[str, Any] = {
        "hosts": hosts,
        "verify_certs": settings.es_verify_certs,
        "request_timeout": settings.es_request_timeout,
    }
    if settings.es_api_key:
        kwargs["api_key"] = settings.es_api_key
    elif settings.es_username and settings.es_password:
        kwargs["basic_auth"] = (settings.es_username, settings.es_password)
    return AsyncElasticsearch(**kwargs)


# ---------------------------------------------------------------------------
# Template and ILM provisioning
# ---------------------------------------------------------------------------

async def ensure_ilm_policy(es: AsyncElasticsearch) -> None:
    """Create or update the CyberNest ILM policy."""
    policy_path = ILM_DIR / "cybernest_ilm.json"
    policy_body = _load_json(policy_path)
    try:
        await es.ilm.put_lifecycle(name="cybernest-ilm-policy", body=policy_body)
        logger.info("ilm policy created/updated", policy="cybernest-ilm-policy")
    except Exception as exc:
        logger.error("failed to create ilm policy", error=str(exc))
        raise


async def ensure_index_templates(es: AsyncElasticsearch) -> None:
    """Create or update index templates for events and alerts."""
    templates = {
        "cybernest-events": TEMPLATES_DIR / "events_template.json",
        "cybernest-alerts": TEMPLATES_DIR / "alerts_template.json",
    }
    for name, path in templates.items():
        if not path.exists():
            logger.warning("template file not found, skipping", template=name, path=str(path))
            continue
        body = _load_json(path)
        try:
            await es.indices.put_template(name=name, body=body)
            logger.info("index template created/updated", template=name)
        except Exception as exc:
            logger.error("failed to create index template", template=name, error=str(exc))
            raise


# ---------------------------------------------------------------------------
# Buffer and bulk indexing
# ---------------------------------------------------------------------------

class DocumentBuffer:
    """Thread-safe async buffer that flushes on size or time threshold."""

    def __init__(
        self,
        es: AsyncElasticsearch,
        max_size: int = 500,
        flush_interval: float = 5.0,
    ) -> None:
        self._es = es
        self._max_size = max_size
        self._flush_interval = flush_interval
        self._buffer: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._last_flush = time.monotonic()
        self._flush_task: Optional[asyncio.Task[None]] = None

        # Metrics
        self._total_indexed = 0
        self._total_errors = 0
        self._last_metric_time = time.monotonic()
        self._last_metric_count = 0

    async def start(self) -> None:
        """Start the periodic flush timer."""
        self._flush_task = asyncio.create_task(self._periodic_flush())

    async def stop(self) -> None:
        """Flush remaining docs and stop the timer."""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self._flush()

    async def add(self, index: str, doc: dict[str, Any]) -> None:
        """Add a document to the buffer, flushing if full."""
        action = {
            "_index": index,
            "_source": doc,
        }
        flush_needed = False
        async with self._lock:
            self._buffer.append(action)
            if len(self._buffer) >= self._max_size:
                flush_needed = True

        if flush_needed:
            await self._flush()

    async def _periodic_flush(self) -> None:
        """Periodically flush the buffer based on time interval."""
        while True:
            try:
                await asyncio.sleep(self._flush_interval)
                elapsed = time.monotonic() - self._last_flush
                if elapsed >= self._flush_interval:
                    await self._flush()
            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.error("periodic flush error", error=str(exc))

    async def _flush(self) -> None:
        """Flush buffered documents to Elasticsearch via bulk API."""
        async with self._lock:
            if not self._buffer:
                return
            batch = self._buffer[:]
            self._buffer.clear()
            self._last_flush = time.monotonic()

        if not batch:
            return

        batch_size = len(batch)
        logger.info("flushing bulk batch", batch_size=batch_size)

        try:
            success_count, errors = await async_bulk(
                self._es,
                batch,
                raise_on_error=False,
                raise_on_exception=False,
                max_retries=0,
                chunk_size=batch_size,
            )
            failed_count = len(errors) if isinstance(errors, list) else 0
            self._total_indexed += success_count
            self._total_errors += failed_count

            if failed_count > 0:
                logger.warning(
                    "bulk indexing partial failure",
                    success=success_count,
                    failed=failed_count,
                )
                await self._retry_failed_docs(errors)
            else:
                logger.info("bulk indexing success", count=success_count)

        except BulkIndexError as exc:
            logger.error(
                "bulk index error",
                errors_count=len(exc.errors),
                error=str(exc)[:500],
            )
            self._total_errors += len(exc.errors)
            await self._retry_failed_docs(exc.errors)

        except Exception as exc:
            logger.error("bulk indexing exception", error=str(exc))
            self._total_errors += batch_size
            await self._retry_individually(batch)

        self._log_metrics()

    async def _retry_failed_docs(self, errors: list[Any]) -> None:
        """Retry failed documents from a bulk response individually."""
        retry_actions = []
        for err in errors:
            if isinstance(err, dict):
                for op_type, details in err.items():
                    if isinstance(details, dict) and details.get("status", 0) >= 400:
                        status = details.get("status", 0)
                        if status == 429 or status >= 500:
                            source = details.get("data", {})
                            index = details.get("_index", "")
                            if source and index:
                                retry_actions.append({"_index": index, "_source": source})
                            logger.warning(
                                "retryable doc failure",
                                index=index,
                                status=status,
                                error=details.get("error", {}).get("reason", "unknown"),
                            )
                        else:
                            logger.error(
                                "non-retryable doc failure",
                                index=details.get("_index", ""),
                                status=status,
                                error=details.get("error", {}).get("reason", "unknown"),
                            )

        if retry_actions:
            await self._retry_individually(retry_actions)

    async def _retry_individually(self, actions: list[dict[str, Any]]) -> None:
        """Retry each document individually with exponential backoff."""
        for action in actions:
            index = action.get("_index", "unknown")
            source = action.get("_source", {})
            if not source:
                continue

            for attempt in range(1, settings.max_retries + 1):
                try:
                    await self._es.index(index=index, document=source)
                    self._total_indexed += 1
                    break
                except Exception as exc:
                    wait = settings.retry_backoff_base * (2 ** (attempt - 1))
                    if attempt < settings.max_retries:
                        logger.warning(
                            "individual index retry",
                            index=index,
                            attempt=attempt,
                            wait_seconds=wait,
                            error=str(exc),
                        )
                        await asyncio.sleep(wait)
                    else:
                        logger.error(
                            "individual index failed after retries",
                            index=index,
                            attempts=settings.max_retries,
                            error=str(exc),
                        )
                        self._total_errors += 1

    def _log_metrics(self) -> None:
        """Log throughput metrics periodically."""
        now = time.monotonic()
        elapsed = now - self._last_metric_time
        if elapsed >= 10.0:
            docs_since = self._total_indexed - self._last_metric_count
            docs_per_sec = docs_since / elapsed if elapsed > 0 else 0.0
            logger.info(
                "indexer metrics",
                total_indexed=self._total_indexed,
                total_errors=self._total_errors,
                docs_per_sec=round(docs_per_sec, 2),
                error_rate=round(
                    self._total_errors / max(self._total_indexed + self._total_errors, 1) * 100,
                    2,
                ),
            )
            self._last_metric_time = now
            self._last_metric_count = self._total_indexed


# ---------------------------------------------------------------------------
# Index name resolution
# ---------------------------------------------------------------------------

def resolve_index_name(topic: str, doc: dict[str, Any]) -> str:
    """Determine the target index name based on topic and document timestamp."""
    ts_str = doc.get("@timestamp") or doc.get("timestamp") or doc.get("created_at")
    if isinstance(ts_str, str):
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)
    elif isinstance(ts_str, datetime):
        ts = ts_str
    else:
        ts = datetime.now(timezone.utc)

    date_suffix = ts.strftime("%Y.%m.%d")

    if topic == settings.alerts_topic:
        return f"cybernest-alerts-{date_suffix}"
    else:
        return f"cybernest-events-{date_suffix}"


# ---------------------------------------------------------------------------
# Kafka consumer with backpressure handling
# ---------------------------------------------------------------------------

class IndexerService:
    """Main indexer service consuming from Kafka and writing to Elasticsearch."""

    def __init__(self) -> None:
        self._es: Optional[AsyncElasticsearch] = None
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._buffer: Optional[DocumentBuffer] = None
        self._running = False
        self._backpressure_delay = 0.0
        self._max_backpressure_delay = 30.0

    async def start(self) -> None:
        """Initialize ES client, provision templates, create consumer, start processing."""
        self._es = create_es_client()

        # Wait for ES to be ready with retries
        await self._wait_for_es()

        # Provision ILM and templates
        await ensure_ilm_policy(self._es)
        await ensure_index_templates(self._es)

        # Create document buffer
        self._buffer = DocumentBuffer(
            es=self._es,
            max_size=settings.buffer_max_size,
            flush_interval=settings.buffer_flush_interval,
        )
        await self._buffer.start()

        # Create Kafka consumer
        await self._create_consumer()

        self._running = True
        logger.info(
            "indexer service started",
            topics=[settings.events_topic, settings.alerts_topic],
            group_id=settings.kafka_group_id,
            es_hosts=settings.es_hosts,
            buffer_max=settings.buffer_max_size,
            flush_interval=settings.buffer_flush_interval,
        )

    async def _wait_for_es(self) -> None:
        """Wait for Elasticsearch to become available."""
        for attempt in range(1, settings.max_retries + 1):
            try:
                info = await self._es.info()
                logger.info(
                    "elasticsearch connected",
                    version=info.get("version", {}).get("number", "unknown"),
                    cluster=info.get("cluster_name", "unknown"),
                )
                return
            except Exception as exc:
                wait = settings.retry_backoff_base * (2 ** (attempt - 1))
                logger.warning(
                    "elasticsearch not ready, retrying",
                    attempt=attempt,
                    wait_seconds=wait,
                    error=str(exc),
                )
                await asyncio.sleep(wait)

        raise ConnectionError(
            f"Elasticsearch not reachable at {settings.es_hosts} "
            f"after {settings.max_retries} attempts"
        )

    async def _create_consumer(self) -> None:
        """Create and start the Kafka consumer with retries."""
        topics = [settings.events_topic, settings.alerts_topic]
        last_error: Optional[Exception] = None

        for attempt in range(1, settings.max_retries + 1):
            try:
                self._consumer = AIOKafkaConsumer(
                    *topics,
                    bootstrap_servers=settings.kafka_bootstrap,
                    group_id=settings.kafka_group_id,
                    value_deserializer=lambda v: json.loads(v),
                    key_deserializer=lambda k: k.decode("utf-8") if k else None,
                    auto_offset_reset=settings.kafka_auto_offset_reset,
                    enable_auto_commit=False,
                    max_poll_records=settings.kafka_max_poll_records,
                    session_timeout_ms=30000,
                    heartbeat_interval_ms=10000,
                    max_poll_interval_ms=300000,
                )
                await self._consumer.start()
                logger.info(
                    "kafka consumer started",
                    topics=topics,
                    group_id=settings.kafka_group_id,
                )
                return
            except (KafkaConnectionError, NodeNotReadyError, KafkaError) as exc:
                last_error = exc
                wait = settings.retry_backoff_base * (2 ** (attempt - 1))
                logger.warning(
                    "kafka consumer connection failed",
                    attempt=attempt,
                    wait_seconds=wait,
                    error=str(exc),
                )
                await asyncio.sleep(wait)

        raise ConnectionError(
            f"Kafka consumer failed to connect to {settings.kafka_bootstrap} "
            f"after {settings.max_retries} attempts: {last_error}"
        )

    async def run(self) -> None:
        """Main consumption loop."""
        if not self._consumer or not self._buffer:
            raise RuntimeError("Service not started. Call start() first.")

        try:
            async for message in self._consumer:
                if not self._running:
                    break

                try:
                    topic = message.topic
                    value = message.value

                    if not isinstance(value, dict):
                        logger.warning(
                            "skipping non-dict message",
                            topic=topic,
                            offset=message.offset,
                        )
                        await self._consumer.commit()
                        continue

                    # Inject ingestion timestamp if not present
                    if "@timestamp" not in value and "timestamp" not in value:
                        value["@timestamp"] = datetime.now(timezone.utc).isoformat()

                    # Resolve target index
                    index_name = resolve_index_name(topic, value)

                    # Add to buffer
                    await self._buffer.add(index_name, value)

                    # Commit offset
                    await self._consumer.commit()

                    # Reset backpressure on success
                    if self._backpressure_delay > 0:
                        self._backpressure_delay = max(
                            0, self._backpressure_delay - 0.1
                        )

                except Exception as exc:
                    logger.error(
                        "message processing error",
                        topic=message.topic,
                        partition=message.partition,
                        offset=message.offset,
                        error=str(exc),
                        exc_info=True,
                    )
                    # Commit to avoid poison pill
                    try:
                        await self._consumer.commit()
                    except Exception:
                        pass

                    # Apply backpressure
                    await self._handle_backpressure()

        except asyncio.CancelledError:
            logger.info("indexer consumption cancelled")
        except KafkaError as exc:
            logger.error("kafka consumer fatal error", error=str(exc))
            raise

    async def _handle_backpressure(self) -> None:
        """Apply exponential backpressure delay on errors."""
        if self._backpressure_delay == 0:
            self._backpressure_delay = 0.1
        else:
            self._backpressure_delay = min(
                self._backpressure_delay * 2,
                self._max_backpressure_delay,
            )
        logger.warning(
            "backpressure applied",
            delay_seconds=round(self._backpressure_delay, 2),
        )
        await asyncio.sleep(self._backpressure_delay)

    async def stop(self) -> None:
        """Gracefully shut down the service."""
        logger.info("indexer service shutting down")
        self._running = False

        if self._buffer:
            await self._buffer.stop()

        if self._consumer:
            try:
                await self._consumer.stop()
            except Exception as exc:
                logger.warning("error stopping consumer", error=str(exc))

        if self._es:
            try:
                await self._es.close()
            except Exception as exc:
                logger.warning("error closing es client", error=str(exc))

        logger.info("indexer service stopped")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

async def main() -> None:
    """Run the indexer service."""
    service = IndexerService()

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("shutdown signal received")
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows does not support add_signal_handler
            pass

    try:
        await service.start()

        # Run consumption in background, wait for shutdown signal
        consume_task = asyncio.create_task(service.run())
        shutdown_task = asyncio.create_task(shutdown_event.wait())

        done, pending = await asyncio.wait(
            [consume_task, shutdown_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Check if consume_task raised an exception
        for task in done:
            if task is consume_task and task.exception():
                raise task.exception()

    except KeyboardInterrupt:
        logger.info("keyboard interrupt received")
    except Exception as exc:
        logger.error("indexer service error", error=str(exc), exc_info=True)
        raise
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())

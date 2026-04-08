"""
CyberNest Alert Manager Service.

Main service that consumes alerts from Kafka, deduplicates, enriches, persists
to PostgreSQL and Elasticsearch, publishes live events to Redis, dispatches
notifications, checks playbook triggers, and manages alert lifecycle.

Run: python -m alert_manager.main
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from datetime import datetime, timezone
from typing import Any, Optional

import asyncpg
import redis.asyncio as redis
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import KafkaConnectionError, KafkaError, NodeNotReadyError
from elasticsearch import AsyncElasticsearch
from pydantic_settings import BaseSettings

from shared.utils.logger import get_logger
from alert_manager.deduplicator import AlertDeduplicator
from alert_manager.enricher import AlertEnricher
from alert_manager.lifecycle import AlertLifecycleManager
from alert_manager.notifier import NotificationDispatcher

logger = get_logger("alert_manager")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class AlertManagerSettings(BaseSettings):
    """Alert Manager configuration loaded from environment variables."""

    # Kafka
    kafka_bootstrap: str = "localhost:9092"
    kafka_group_id: str = "alert-manager-group"
    kafka_auto_offset_reset: str = "latest"
    kafka_max_poll_records: int = 100

    # PostgreSQL
    pg_dsn: str = "postgresql://cybernest:cybernest@localhost:5432/cybernest"
    pg_min_connections: int = 2
    pg_max_connections: int = 10

    # Elasticsearch
    es_hosts: str = "http://localhost:9200"
    es_username: str = ""
    es_password: str = ""
    es_api_key: str = ""
    es_verify_certs: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Topics
    alerts_topic: str = "cybernest.alerts"
    soar_trigger_topic: str = "cybernest.soar.trigger"

    # Lifecycle check interval (seconds)
    lifecycle_check_interval: int = 300  # 5 minutes

    # Retry
    max_retries: int = 3
    retry_backoff_base: float = 1.0

    # Notification config (JSON string or will be loaded from env)
    notification_slack_enabled: bool = False
    notification_slack_webhook: str = ""
    notification_slack_min_severity: str = "medium"

    notification_email_enabled: bool = False
    notification_email_host: str = "localhost"
    notification_email_port: int = 587
    notification_email_username: str = ""
    notification_email_password: str = ""
    notification_email_from: str = "cybernest@localhost"
    notification_email_to: str = ""
    notification_email_use_tls: bool = True
    notification_email_min_severity: str = "high"

    notification_pagerduty_enabled: bool = False
    notification_pagerduty_api_key: str = ""
    notification_pagerduty_min_severity: str = "critical"

    notification_teams_enabled: bool = False
    notification_teams_webhook: str = ""
    notification_teams_min_severity: str = "medium"

    notification_webhook_enabled: bool = False
    notification_webhook_url: str = ""
    notification_webhook_secret: str = ""
    notification_webhook_min_severity: str = "low"

    # Playbook trigger rules (JSON list of {rule_id_pattern, playbook_id})
    playbook_triggers_json: str = "[]"

    model_config = {"env_prefix": "ALERT_MANAGER_", "extra": "ignore"}

    def build_notification_config(self) -> dict[str, Any]:
        """Build notification config dict from flat env vars."""
        config: dict[str, Any] = {
            "slack": {
                "enabled": self.notification_slack_enabled,
                "webhook_url": self.notification_slack_webhook,
                "min_severity": self.notification_slack_min_severity,
            },
            "email": {
                "enabled": self.notification_email_enabled,
                "smtp": {
                    "host": self.notification_email_host,
                    "port": self.notification_email_port,
                    "username": self.notification_email_username,
                    "password": self.notification_email_password,
                    "from_addr": self.notification_email_from,
                    "to_addrs": [
                        a.strip()
                        for a in self.notification_email_to.split(",")
                        if a.strip()
                    ],
                    "use_tls": self.notification_email_use_tls,
                },
                "min_severity": self.notification_email_min_severity,
            },
            "pagerduty": {
                "enabled": self.notification_pagerduty_enabled,
                "api_key": self.notification_pagerduty_api_key,
                "min_severity": self.notification_pagerduty_min_severity,
            },
            "teams": {
                "enabled": self.notification_teams_enabled,
                "webhook_url": self.notification_teams_webhook,
                "min_severity": self.notification_teams_min_severity,
            },
            "webhooks": [],
        }
        if self.notification_webhook_enabled:
            config["webhooks"].append({
                "enabled": True,
                "url": self.notification_webhook_url,
                "secret": self.notification_webhook_secret,
                "min_severity": self.notification_webhook_min_severity,
            })
        return config

    def load_playbook_triggers(self) -> list[dict[str, str]]:
        """Parse playbook trigger rules from JSON config."""
        try:
            return json.loads(self.playbook_triggers_json)
        except (json.JSONDecodeError, TypeError):
            return []


settings = AlertManagerSettings()

# ---------------------------------------------------------------------------
# Elasticsearch client factory
# ---------------------------------------------------------------------------

def create_es_client() -> AsyncElasticsearch:
    hosts = [h.strip() for h in settings.es_hosts.split(",")]
    kwargs: dict[str, Any] = {
        "hosts": hosts,
        "verify_certs": settings.es_verify_certs,
        "request_timeout": 30,
    }
    if settings.es_api_key:
        kwargs["api_key"] = settings.es_api_key
    elif settings.es_username and settings.es_password:
        kwargs["basic_auth"] = (settings.es_username, settings.es_password)
    return AsyncElasticsearch(**kwargs)


# ---------------------------------------------------------------------------
# PostgreSQL persistence
# ---------------------------------------------------------------------------

async def persist_alert_to_pg(
    pool: asyncpg.Pool, alert_data: dict[str, Any]
) -> None:
    """Insert or update an alert record in PostgreSQL."""
    alert_id = alert_data.get("alert_id", "")
    now = datetime.now(timezone.utc)

    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alerts (
                    alert_id, rule_id, rule_name, severity, status,
                    title, description, source_ip, destination_ip,
                    username, hostname, raw_log, parsed_event,
                    event_ids, event_count, mitre_tactic, mitre_technique,
                    risk_score, threat_intel, geo_data, asset_info,
                    assignee_id, incident_id, created_at, updated_at,
                    acknowledged_at, resolved_at, comments
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15, $16, $17, $18, $19,
                    $20, $21, $22, $23, $24, $25, $26, $27, $28
                )
                ON CONFLICT (alert_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    risk_score = EXCLUDED.risk_score,
                    threat_intel = EXCLUDED.threat_intel,
                    asset_info = EXCLUDED.asset_info,
                    event_count = EXCLUDED.event_count,
                    updated_at = $25,
                    comments = alerts.comments || EXCLUDED.comments
                """,
                alert_data.get("alert_id"),
                alert_data.get("rule_id", ""),
                alert_data.get("rule_name", ""),
                alert_data.get("severity", "medium"),
                alert_data.get("status", "new"),
                alert_data.get("title", ""),
                alert_data.get("description", ""),
                alert_data.get("source_ip"),
                alert_data.get("destination_ip"),
                alert_data.get("username"),
                alert_data.get("hostname"),
                alert_data.get("raw_log"),
                json.dumps(alert_data.get("parsed_event")) if alert_data.get("parsed_event") else None,
                alert_data.get("event_ids", []),
                alert_data.get("event_count", 1),
                alert_data.get("mitre_tactic"),
                alert_data.get("mitre_technique", []),
                alert_data.get("risk_score", 0.0),
                json.dumps(alert_data.get("threat_intel")) if alert_data.get("threat_intel") else None,
                json.dumps(alert_data.get("geo_data")) if alert_data.get("geo_data") else None,
                json.dumps(alert_data.get("asset_info")) if alert_data.get("asset_info") else None,
                alert_data.get("assignee_id"),
                alert_data.get("incident_id"),
                _parse_dt(alert_data.get("created_at")) or now,
                now,
                _parse_dt(alert_data.get("acknowledged_at")),
                _parse_dt(alert_data.get("resolved_at")),
                json.dumps(alert_data.get("comments", [])),
            )
            logger.debug("alert persisted to postgresql", alert_id=alert_id)

    except Exception as exc:
        logger.error(
            "failed to persist alert to postgresql",
            alert_id=alert_id,
            error=str(exc),
        )
        raise


def _parse_dt(val: Any) -> Optional[datetime]:
    """Parse a datetime value from various formats."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str) and val:
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# Elasticsearch indexing
# ---------------------------------------------------------------------------

async def index_alert_to_es(
    es: AsyncElasticsearch, alert_data: dict[str, Any]
) -> None:
    """Index an alert document to Elasticsearch."""
    alert_id = alert_data.get("alert_id", "unknown")
    created_at = _parse_dt(alert_data.get("created_at")) or datetime.now(timezone.utc)
    index_name = f"cybernest-alerts-{created_at.strftime('%Y.%m.%d')}"

    # Add @timestamp for ES
    doc = {**alert_data, "@timestamp": created_at.isoformat()}

    try:
        await es.index(index=index_name, id=alert_id, document=doc)
        logger.debug("alert indexed to elasticsearch", alert_id=alert_id, index=index_name)
    except Exception as exc:
        logger.error(
            "failed to index alert to elasticsearch",
            alert_id=alert_id,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Redis live alert publishing
# ---------------------------------------------------------------------------

async def publish_live_alert(
    redis_client: redis.Redis, alert_data: dict[str, Any]
) -> None:
    """Publish alert to Redis pub/sub channel for live dashboard updates."""
    try:
        payload = json.dumps(alert_data, default=str)
        await redis_client.publish("cybernest:live:alerts", payload)
        logger.debug(
            "alert published to redis",
            alert_id=alert_data.get("alert_id"),
        )
    except Exception as exc:
        logger.warning(
            "failed to publish alert to redis",
            alert_id=alert_data.get("alert_id"),
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Playbook trigger matching
# ---------------------------------------------------------------------------

def check_playbook_triggers(
    alert_data: dict[str, Any],
    triggers: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Check if an alert matches any playbook trigger rules.

    Each trigger has:
    - rule_id_pattern: exact rule_id or "*" for any
    - severity_min: minimum severity to trigger (optional)
    - playbook_id: the SOAR playbook to trigger

    Returns list of matched trigger payloads for Kafka.
    """
    matched: list[dict[str, Any]] = []
    alert_rule_id = alert_data.get("rule_id", "")
    alert_severity = str(alert_data.get("severity", "")).lower()
    severity_order = ["informational", "low", "medium", "high", "critical"]

    for trigger in triggers:
        pattern = trigger.get("rule_id_pattern", "")
        if pattern != "*" and pattern != alert_rule_id:
            continue

        min_sev = trigger.get("severity_min", "low").lower()
        alert_idx = severity_order.index(alert_severity) if alert_severity in severity_order else 0
        min_idx = severity_order.index(min_sev) if min_sev in severity_order else 0
        if alert_idx < min_idx:
            continue

        matched.append({
            "playbook_id": trigger.get("playbook_id", ""),
            "alert_id": alert_data.get("alert_id", ""),
            "alert_severity": alert_severity,
            "rule_id": alert_rule_id,
            "rule_name": alert_data.get("rule_name", ""),
            "source_ip": alert_data.get("source_ip"),
            "destination_ip": alert_data.get("destination_ip"),
            "username": alert_data.get("username"),
            "hostname": alert_data.get("hostname"),
            "triggered_at": datetime.now(timezone.utc).isoformat(),
        })

    return matched


# ---------------------------------------------------------------------------
# Main Alert Manager Service
# ---------------------------------------------------------------------------

class AlertManagerService:
    """Core alert manager service orchestrating all components."""

    def __init__(self) -> None:
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._producer: Optional[AIOKafkaProducer] = None
        self._pg_pool: Optional[asyncpg.Pool] = None
        self._es: Optional[AsyncElasticsearch] = None
        self._redis: Optional[redis.Redis] = None

        self._deduplicator: Optional[AlertDeduplicator] = None
        self._enricher: Optional[AlertEnricher] = None
        self._lifecycle: Optional[AlertLifecycleManager] = None
        self._notifier: Optional[NotificationDispatcher] = None

        self._playbook_triggers: list[dict[str, str]] = []
        self._running = False
        self._lifecycle_task: Optional[asyncio.Task[None]] = None

        # Metrics
        self._total_processed = 0
        self._total_deduplicated = 0
        self._total_errors = 0
        self._start_time = time.monotonic()

    async def start(self) -> None:
        """Initialize all connections and components."""
        # PostgreSQL
        self._pg_pool = await asyncpg.create_pool(
            dsn=settings.pg_dsn,
            min_size=settings.pg_min_connections,
            max_size=settings.pg_max_connections,
        )
        logger.info("postgresql pool created")

        # Elasticsearch
        self._es = create_es_client()
        try:
            info = await self._es.info()
            logger.info(
                "elasticsearch connected",
                version=info.get("version", {}).get("number", "unknown"),
            )
        except Exception as exc:
            logger.warning("elasticsearch not immediately available", error=str(exc))

        # Redis
        self._redis = redis.from_url(
            settings.redis_url,
            decode_responses=False,
        )
        try:
            await self._redis.ping()
            logger.info("redis connected")
        except Exception as exc:
            logger.warning("redis not immediately available", error=str(exc))

        # Initialize components
        self._deduplicator = AlertDeduplicator(self._redis)
        self._enricher = AlertEnricher(self._pg_pool)

        notification_config = settings.build_notification_config()
        self._notifier = NotificationDispatcher(notification_config)

        self._lifecycle = AlertLifecycleManager(
            pg_pool=self._pg_pool,
            notify_callback=self._lifecycle_notify,
        )

        self._playbook_triggers = settings.load_playbook_triggers()

        # Kafka producer (for SOAR triggers)
        self._producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            compression_type="lz4",
            acks="all",
        )
        await self._start_with_retry(
            self._producer.start, "kafka producer"
        )

        # Kafka consumer
        self._consumer = AIOKafkaConsumer(
            settings.alerts_topic,
            bootstrap_servers=settings.kafka_bootstrap,
            group_id=settings.kafka_group_id,
            value_deserializer=lambda v: json.loads(v),
            key_deserializer=lambda k: k.decode("utf-8") if k else None,
            auto_offset_reset=settings.kafka_auto_offset_reset,
            enable_auto_commit=False,
            max_poll_records=settings.kafka_max_poll_records,
            session_timeout_ms=30000,
            heartbeat_interval_ms=10000,
        )
        await self._start_with_retry(
            self._consumer.start, "kafka consumer"
        )

        self._running = True

        # Start periodic lifecycle checks
        self._lifecycle_task = asyncio.create_task(self._lifecycle_loop())

        logger.info(
            "alert manager service started",
            topic=settings.alerts_topic,
            group_id=settings.kafka_group_id,
        )

    async def _start_with_retry(self, start_fn: Any, name: str) -> None:
        """Start a component with retry logic."""
        for attempt in range(1, settings.max_retries + 1):
            try:
                await start_fn()
                logger.info(f"{name} started", attempt=attempt)
                return
            except (KafkaConnectionError, NodeNotReadyError, KafkaError, Exception) as exc:
                wait = settings.retry_backoff_base * (2 ** (attempt - 1))
                logger.warning(
                    f"{name} start failed, retrying",
                    attempt=attempt,
                    wait_seconds=wait,
                    error=str(exc),
                )
                await asyncio.sleep(wait)

        raise ConnectionError(f"{name} failed to start after {settings.max_retries} attempts")

    async def _lifecycle_notify(
        self, alert_data: dict[str, Any], reason: str
    ) -> None:
        """Callback for lifecycle manager to send escalation notifications."""
        alert_data["_escalation_reason"] = reason
        if self._notifier:
            # Force critical severity for escalation notifications
            escalation_alert = {**alert_data, "severity": "critical"}
            await self._notifier.dispatch(escalation_alert)

    async def _lifecycle_loop(self) -> None:
        """Periodically run lifecycle checks."""
        while self._running:
            try:
                await asyncio.sleep(settings.lifecycle_check_interval)
                if not self._running:
                    break
                if self._lifecycle:
                    results = await self._lifecycle.run_lifecycle_checks()
                    if results:
                        logger.info("lifecycle checks completed", results=results)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.error("lifecycle check error", error=str(exc))

    async def run(self) -> None:
        """Main message processing loop."""
        if not self._consumer:
            raise RuntimeError("Service not started")

        try:
            async for message in self._consumer:
                if not self._running:
                    break

                try:
                    await self._process_alert(message.value)
                    await self._consumer.commit()
                    self._total_processed += 1
                except Exception as exc:
                    self._total_errors += 1
                    logger.error(
                        "alert processing error",
                        offset=message.offset,
                        error=str(exc),
                        exc_info=True,
                    )
                    try:
                        await self._consumer.commit()
                    except Exception:
                        pass

                # Log metrics periodically
                if self._total_processed % 100 == 0 and self._total_processed > 0:
                    self._log_metrics()

        except asyncio.CancelledError:
            logger.info("alert manager consumption cancelled")
        except KafkaError as exc:
            logger.error("kafka consumer fatal error", error=str(exc))
            raise

    async def _process_alert(self, alert_data: dict[str, Any]) -> None:
        """Process a single alert through the full pipeline."""
        alert_id = alert_data.get("alert_id", "unknown")
        logger.info(
            "processing alert",
            alert_id=alert_id,
            rule_id=alert_data.get("rule_id"),
            severity=alert_data.get("severity"),
        )

        # 1. Deduplicate
        if self._deduplicator:
            is_new, existing_id, count = await self._deduplicator.check_and_set(
                alert_data
            )
            if not is_new:
                self._total_deduplicated += 1
                # Update event count on existing alert in DB
                if existing_id and self._pg_pool:
                    try:
                        async with self._pg_pool.acquire() as conn:
                            await conn.execute(
                                """
                                UPDATE alerts
                                SET event_count = event_count + 1,
                                    updated_at = $2
                                WHERE alert_id = $1
                                """,
                                existing_id,
                                datetime.now(timezone.utc),
                            )
                    except Exception as exc:
                        logger.warning(
                            "failed to increment dedup counter",
                            alert_id=existing_id,
                            error=str(exc),
                        )
                return

        # 2. Enrich
        if self._enricher:
            alert_data = await self._enricher.enrich(alert_data)

        # 3. SLA tracking
        alert_data = AlertLifecycleManager.track_sla(alert_data)

        # 4. Persist to PostgreSQL
        if self._pg_pool:
            await persist_alert_to_pg(self._pg_pool, alert_data)

        # 5. Index to Elasticsearch
        if self._es:
            await index_alert_to_es(self._es, alert_data)

        # 6. Publish to Redis pub/sub for live dashboard
        if self._redis:
            await publish_live_alert(self._redis, alert_data)

        # 7. Dispatch notifications
        if self._notifier:
            notification_results = await self._notifier.dispatch(alert_data)
            if notification_results:
                logger.info(
                    "notifications dispatched",
                    alert_id=alert_id,
                    results=notification_results,
                )

        # 8. Check playbook triggers and publish to SOAR
        if self._playbook_triggers and self._producer:
            matched_triggers = check_playbook_triggers(
                alert_data, self._playbook_triggers
            )
            for trigger_payload in matched_triggers:
                try:
                    await self._producer.send_and_wait(
                        settings.soar_trigger_topic,
                        key=trigger_payload.get("playbook_id"),
                        value=trigger_payload,
                    )
                    logger.info(
                        "soar playbook triggered",
                        alert_id=alert_id,
                        playbook_id=trigger_payload.get("playbook_id"),
                    )
                except Exception as exc:
                    logger.error(
                        "failed to publish soar trigger",
                        alert_id=alert_id,
                        error=str(exc),
                    )

        # 9. Auto-create case for critical alerts
        if self._lifecycle:
            severity = str(alert_data.get("severity", "")).lower()
            if severity == "critical":
                case_id = await self._lifecycle.auto_create_case(alert_data)
                if case_id:
                    alert_data["incident_id"] = case_id

        logger.info(
            "alert processed successfully",
            alert_id=alert_id,
            severity=alert_data.get("severity"),
            risk_score=alert_data.get("risk_score"),
        )

    def _log_metrics(self) -> None:
        """Log processing metrics."""
        elapsed = time.monotonic() - self._start_time
        rate = self._total_processed / elapsed if elapsed > 0 else 0
        logger.info(
            "alert manager metrics",
            total_processed=self._total_processed,
            total_deduplicated=self._total_deduplicated,
            total_errors=self._total_errors,
            alerts_per_sec=round(rate, 2),
        )

    async def stop(self) -> None:
        """Gracefully shut down all components."""
        logger.info("alert manager service shutting down")
        self._running = False

        if self._lifecycle_task:
            self._lifecycle_task.cancel()
            try:
                await self._lifecycle_task
            except asyncio.CancelledError:
                pass

        if self._consumer:
            try:
                await self._consumer.stop()
            except Exception as exc:
                logger.warning("error stopping consumer", error=str(exc))

        if self._producer:
            try:
                await self._producer.stop()
            except Exception as exc:
                logger.warning("error stopping producer", error=str(exc))

        if self._es:
            try:
                await self._es.close()
            except Exception as exc:
                logger.warning("error closing es", error=str(exc))

        if self._redis:
            try:
                await self._redis.close()
            except Exception as exc:
                logger.warning("error closing redis", error=str(exc))

        if self._pg_pool:
            try:
                await self._pg_pool.close()
            except Exception as exc:
                logger.warning("error closing pg pool", error=str(exc))

        self._log_metrics()
        logger.info("alert manager service stopped")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

async def main() -> None:
    """Run the alert manager service."""
    service = AlertManagerService()

    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("shutdown signal received")
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    try:
        await service.start()

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

        for task in done:
            if task is consume_task and task.exception():
                raise task.exception()

    except KeyboardInterrupt:
        logger.info("keyboard interrupt received")
    except Exception as exc:
        logger.error("alert manager service error", error=str(exc), exc_info=True)
        raise
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())

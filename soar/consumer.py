"""
CyberNest SOAR Consumer Service.

Main entry point for the SOAR microservice.  Connects to Kafka, Redis,
and PostgreSQL, loads playbooks, and consumes alert triggers from the
``cybernest.soar.trigger`` topic.  For each alert, it finds matching
playbooks and executes them concurrently.

Run:
    python -m soar.consumer
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from typing import Any, Optional

import asyncpg
import redis.asyncio as aioredis

from shared.utils.logger import get_logger
from soar.engine import SOAREngine

logger = get_logger("soar_consumer")

# ---------------------------------------------------------------------------
# Configuration via environment variables
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.environ.get("SOAR_KAFKA_TOPIC", "cybernest.soar.trigger")
KAFKA_GROUP_ID = os.environ.get("SOAR_KAFKA_GROUP", "soar-engine-group")

POSTGRES_DSN = os.environ.get(
    "POSTGRES_DSN",
    "postgresql://cybernest:cybernest@localhost:5432/cybernest",
)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

MAX_CONCURRENT_PLAYBOOKS = int(os.environ.get("MAX_CONCURRENT_PLAYBOOKS", "10"))
PLAYBOOK_RELOAD_INTERVAL = int(os.environ.get("PLAYBOOK_RELOAD_INTERVAL", "300"))  # seconds


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class SOARService:
    """Orchestrates the SOAR consumer lifecycle."""

    def __init__(self) -> None:
        self.engine: Optional[SOAREngine] = None
        self.db_pool: Optional[asyncpg.Pool] = None
        self.redis_client: Optional[aioredis.Redis] = None
        self._consumer_task: Optional[asyncio.Task] = None
        self._reload_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_PLAYBOOKS)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Initialize connections, load playbooks, and start consuming."""
        logger.info(
            "soar service starting",
            kafka=KAFKA_BOOTSTRAP,
            topic=KAFKA_TOPIC,
            postgres=POSTGRES_DSN.split("@")[-1] if "@" in POSTGRES_DSN else POSTGRES_DSN,
        )

        # Connect to PostgreSQL
        try:
            self.db_pool = await asyncpg.create_pool(
                dsn=POSTGRES_DSN,
                min_size=2,
                max_size=10,
                command_timeout=30,
            )
            logger.info("postgresql connected")
        except Exception as exc:
            logger.warning("postgresql not available, running without DB", error=str(exc))
            self.db_pool = None

        # Connect to Redis
        try:
            self.redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
            await self.redis_client.ping()
            logger.info("redis connected")
        except Exception as exc:
            logger.warning("redis not available, running without Redis", error=str(exc))
            self.redis_client = None

        # Build config dict from environment
        config = self._build_config()

        # Initialize engine
        self.engine = SOAREngine(
            db_pool=self.db_pool,
            redis_client=self.redis_client,
            config=config,
        )

        # Ensure DB schema
        await self.engine.ensure_schema()

        # Load playbooks
        self.engine.load_playbooks()

        if not self.engine.playbooks:
            logger.warning("no playbooks loaded -- alerts will not trigger any actions")

        # Start background tasks
        self._consumer_task = asyncio.create_task(self._consume_loop())
        self._reload_task = asyncio.create_task(self._playbook_reload_loop())

        logger.info("soar service started")

    async def stop(self) -> None:
        """Graceful shutdown."""
        logger.info("soar service stopping")
        self._shutdown_event.set()

        if self._consumer_task and not self._consumer_task.done():
            self._consumer_task.cancel()
            try:
                await self._consumer_task
            except asyncio.CancelledError:
                pass

        if self._reload_task and not self._reload_task.done():
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass

        if self.redis_client:
            await self.redis_client.aclose()

        if self.db_pool:
            await self.db_pool.close()

        logger.info("soar service stopped")

    # ------------------------------------------------------------------
    # Kafka consumer
    # ------------------------------------------------------------------

    async def _consume_loop(self) -> None:
        """Connect to Kafka and process messages."""
        from aiokafka import AIOKafkaConsumer
        from aiokafka.errors import KafkaConnectionError, KafkaError

        consumer: Optional[AIOKafkaConsumer] = None
        retry_delay = 5

        while not self._shutdown_event.is_set():
            try:
                consumer = AIOKafkaConsumer(
                    KAFKA_TOPIC,
                    bootstrap_servers=KAFKA_BOOTSTRAP,
                    group_id=KAFKA_GROUP_ID,
                    value_deserializer=lambda v: json.loads(v),
                    key_deserializer=lambda k: k.decode("utf-8") if k else None,
                    auto_offset_reset="latest",
                    enable_auto_commit=False,
                    max_poll_records=50,
                    session_timeout_ms=30000,
                    heartbeat_interval_ms=10000,
                )
                await consumer.start()
                logger.info(
                    "kafka consumer connected",
                    topic=KAFKA_TOPIC,
                    group=KAFKA_GROUP_ID,
                )
                retry_delay = 5  # Reset on successful connect

                async for message in consumer:
                    if self._shutdown_event.is_set():
                        break

                    try:
                        await self._handle_message(message.key, message.value)
                        await consumer.commit()
                    except Exception as exc:
                        logger.error(
                            "message handling error",
                            topic=message.topic,
                            partition=message.partition,
                            offset=message.offset,
                            error=str(exc),
                        )
                        # Commit to avoid poison pill
                        await consumer.commit()

            except asyncio.CancelledError:
                break
            except (KafkaConnectionError, KafkaError) as exc:
                logger.warning(
                    "kafka connection lost, reconnecting",
                    error=str(exc),
                    retry_in=retry_delay,
                )
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)
            except Exception as exc:
                logger.error("kafka consumer unexpected error", error=str(exc))
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)
            finally:
                if consumer:
                    try:
                        await consumer.stop()
                    except Exception:
                        pass
                    consumer = None

    async def _handle_message(self, key: Optional[str], value: Any) -> None:
        """Process a single Kafka message (alert trigger)."""
        if not isinstance(value, dict):
            logger.warning("invalid message format (expected dict)", key=key)
            return

        alert = value
        alert_id = alert.get("alert_id", key or "unknown")

        logger.info(
            "alert received",
            alert_id=alert_id,
            rule_id=alert.get("rule_id", ""),
            severity=alert.get("severity", ""),
        )

        # Find matching playbooks
        matching = self.engine.find_matching_playbooks(alert)

        if not matching:
            logger.debug("no matching playbooks", alert_id=alert_id)
            return

        logger.info(
            "playbooks matched",
            alert_id=alert_id,
            playbooks=[pb.name for pb in matching],
        )

        # Execute matching playbooks concurrently with semaphore
        tasks = []
        for playbook in matching:
            task = asyncio.create_task(
                self._execute_with_semaphore(playbook, alert)
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for playbook, result in zip(matching, results):
            if isinstance(result, Exception):
                logger.error(
                    "playbook execution exception",
                    playbook=playbook.name,
                    alert_id=alert_id,
                    error=str(result),
                )
            else:
                logger.info(
                    "playbook execution result",
                    playbook=playbook.name,
                    alert_id=alert_id,
                    status=result.get("status", "unknown"),
                    duration_ms=result.get("duration_ms", 0),
                )

    async def _execute_with_semaphore(
        self, playbook: Any, alert: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a playbook with concurrency limiting."""
        async with self._semaphore:
            return await self.engine.run_playbook(
                playbook, alert, triggered_by="kafka_consumer"
            )

    # ------------------------------------------------------------------
    # Playbook hot-reload
    # ------------------------------------------------------------------

    async def _playbook_reload_loop(self) -> None:
        """Periodically reload playbooks from disk."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(PLAYBOOK_RELOAD_INTERVAL)
                if self.engine:
                    self.engine.reload_playbooks()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("playbook reload error", error=str(exc))

    # ------------------------------------------------------------------
    # Config builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_config() -> dict[str, Any]:
        """Build configuration dict from environment variables."""
        return {
            "vt_api_key": os.environ.get("VT_API_KEY", ""),
            "abuseipdb_api_key": os.environ.get("ABUSEIPDB_API_KEY", ""),
            "shodan_api_key": os.environ.get("SHODAN_API_KEY", ""),
            "slack_webhook_url": os.environ.get("SLACK_WEBHOOK_URL", ""),
            "smtp_host": os.environ.get("SMTP_HOST", "localhost"),
            "smtp_port": int(os.environ.get("SMTP_PORT", "587")),
            "smtp_user": os.environ.get("SMTP_USER", ""),
            "smtp_password": os.environ.get("SMTP_PASSWORD", ""),
            "smtp_from": os.environ.get("SMTP_FROM", "cybernest-soar@localhost"),
            "cybernest_api_url": os.environ.get("CYBERNEST_API_URL", "http://localhost:8000"),
            "cybernest_api_key": os.environ.get("CYBERNEST_API_KEY", ""),
            "jira_url": os.environ.get("JIRA_URL", ""),
            "jira_user": os.environ.get("JIRA_USER", ""),
            "jira_api_token": os.environ.get("JIRA_API_TOKEN", ""),
            "jira_project_key": os.environ.get("JIRA_PROJECT_KEY", "SEC"),
            "ad_server": os.environ.get("AD_SERVER", ""),
            "ad_base_dn": os.environ.get("AD_BASE_DN", ""),
            "ad_bind_user": os.environ.get("AD_BIND_USER", ""),
            "ad_bind_password": os.environ.get("AD_BIND_PASSWORD", ""),
            "pfsense_url": os.environ.get("PFSENSE_URL", ""),
            "pfsense_api_key": os.environ.get("PFSENSE_API_KEY", ""),
            "pfsense_api_secret": os.environ.get("PFSENSE_API_SECRET", ""),
            "fortinet_url": os.environ.get("FORTINET_URL", ""),
            "fortinet_api_key": os.environ.get("FORTINET_API_KEY", ""),
            "paloalto_url": os.environ.get("PALOALTO_URL", ""),
            "paloalto_api_key": os.environ.get("PALOALTO_API_KEY", ""),
            "redis_url": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    """Run the SOAR consumer service."""
    service = SOARService()

    loop = asyncio.get_running_loop()
    stop_signals = (signal.SIGTERM, signal.SIGINT)

    # Windows does not support add_signal_handler on the default event loop
    if sys.platform != "win32":
        for sig in stop_signals:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(service.stop()))

    try:
        await service.start()
        # Run until shutdown event is set
        await service._shutdown_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())

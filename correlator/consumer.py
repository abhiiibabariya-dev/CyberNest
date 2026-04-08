"""
CyberNest Correlator Consumer — Main Service Entry Point.

Consumes normalized ECS events from Kafka, runs them through:
  1. YAML rule engine (CyberNest + Sigma rules)
  2. Sliding-window behavioral rules
  3. UEBA ML anomaly detector

Publishes generated alerts to the cybernest.alerts topic.
Tracks processing metrics.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import redis.asyncio as aioredis

from shared.utils.logger import get_logger
from shared.utils.kafka_utils import (
    KafkaConsumerManager,
    KafkaProducerManager,
    Topics,
)

from correlator.engine.rule_engine import RuleEngine
from correlator.engine.sigma_loader import SigmaLoader
from correlator.engine.window_tracker import SlidingWindowRules
from correlator.engine.ml_detector import MLDetector

logger = get_logger("correlator")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
PG_DSN = os.environ.get("DATABASE_URL", "postgresql://cybernest:cybernest@localhost:5432/cybernest")

RULES_DIR = os.environ.get(
    "RULES_DIR",
    str(Path(__file__).resolve().parent / "rules"),
)
SIGMA_RULES_DIR = os.environ.get(
    "SIGMA_RULES_DIR",
    str(Path(__file__).resolve().parent / "sigma_rules"),
)

CONSUMER_GROUP = "correlator-group"
INPUT_TOPIC = Topics.PARSED_EVENTS      # cybernest.parsed.events
OUTPUT_TOPIC = Topics.ALERTS             # cybernest.alerts

ML_ENABLED = os.environ.get("ML_ENABLED", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Metrics tracker
# ---------------------------------------------------------------------------

class Metrics:
    """Simple in-memory metrics counters for the correlator."""

    def __init__(self) -> None:
        self.events_processed: int = 0
        self.alerts_generated: int = 0
        self.rule_alerts: int = 0
        self.window_alerts: int = 0
        self.ml_alerts: int = 0
        self.errors: int = 0
        self.start_time: float = time.time()
        self._last_log_time: float = time.time()

    def log_if_due(self) -> None:
        """Log metrics every 60 seconds."""
        now = time.time()
        if now - self._last_log_time >= 60:
            uptime = now - self.start_time
            eps = self.events_processed / uptime if uptime > 0 else 0
            logger.info(
                "correlator metrics",
                events_processed=self.events_processed,
                alerts_generated=self.alerts_generated,
                rule_alerts=self.rule_alerts,
                window_alerts=self.window_alerts,
                ml_alerts=self.ml_alerts,
                errors=self.errors,
                events_per_second=round(eps, 2),
                uptime_seconds=round(uptime, 0),
            )
            self._last_log_time = now


# ---------------------------------------------------------------------------
# Correlator service
# ---------------------------------------------------------------------------

class CorrelatorService:
    """Orchestrates all correlation engines and Kafka I/O."""

    def __init__(self) -> None:
        self._redis: Optional[aioredis.Redis] = None
        self._pg_pool: Any = None
        self._rule_engine: Optional[RuleEngine] = None
        self._window_rules: Optional[SlidingWindowRules] = None
        self._ml_detector: Optional[MLDetector] = None
        self._producer: Optional[KafkaProducerManager] = None
        self._consumer: Optional[KafkaConsumerManager] = None
        self._metrics = Metrics()
        self._running = False

    async def start(self) -> None:
        """Initialize all dependencies and start consuming."""
        logger.info("correlator starting")

        # -- Redis -----------------------------------------------------------
        self._redis = aioredis.from_url(
            REDIS_URL,
            decode_responses=False,
            max_connections=20,
        )
        try:
            await self._redis.ping()
            logger.info("redis connected", url=REDIS_URL)
        except Exception:
            logger.exception("redis connection failed")
            raise

        # -- PostgreSQL (optional, for ML baselines) -------------------------
        try:
            import asyncpg
            self._pg_pool = await asyncpg.create_pool(
                PG_DSN, min_size=2, max_size=10, timeout=10,
            )
            logger.info("postgresql connected", dsn=PG_DSN.split("@")[-1])
        except Exception:
            logger.warning(
                "postgresql connection failed, ML baselines will use Redis only",
                exc_info=True,
            )
            self._pg_pool = None

        # -- Rule engine -----------------------------------------------------
        self._rule_engine = RuleEngine(redis_client=self._redis)
        rule_count = self._rule_engine.load_rules_from_directory(RULES_DIR)
        logger.info("cybernest rules loaded", count=rule_count)

        # -- Sigma rules (optional) ------------------------------------------
        sigma_path = Path(SIGMA_RULES_DIR)
        if sigma_path.exists():
            sigma_loader = SigmaLoader()
            sigma_count = sigma_loader.load_directory(SIGMA_RULES_DIR)
            for internal_rule in sigma_loader.internal_rules:
                self._rule_engine.load_rule_from_dict(internal_rule)
            logger.info("sigma rules loaded", count=sigma_count)
        else:
            logger.info("no sigma rules directory found", path=SIGMA_RULES_DIR)

        # -- Window tracker --------------------------------------------------
        self._window_rules = SlidingWindowRules(redis_client=self._redis)

        # -- ML detector -----------------------------------------------------
        if ML_ENABLED:
            self._ml_detector = MLDetector(
                redis_client=self._redis,
                pg_pool=self._pg_pool,
            )
            if self._pg_pool:
                await self._ml_detector.init_pg_schema()
            logger.info("ml detector initialized")
        else:
            logger.info("ml detector disabled")

        # -- Kafka producer --------------------------------------------------
        self._producer = KafkaProducerManager(KAFKA_BOOTSTRAP)
        await self._producer.start()

        # -- Kafka consumer --------------------------------------------------
        self._consumer = KafkaConsumerManager(KAFKA_BOOTSTRAP)
        self._running = True

        logger.info(
            "correlator started, consuming events",
            input_topic=INPUT_TOPIC,
            output_topic=OUTPUT_TOPIC,
            group=CONSUMER_GROUP,
            total_rules=len(self._rule_engine.rules),
        )

        await self._consumer.consume(
            topics=[INPUT_TOPIC],
            group_id=CONSUMER_GROUP,
            handler=self._handle_event,
            auto_offset_reset="latest",
            max_poll_records=500,
        )

    async def stop(self) -> None:
        """Graceful shutdown."""
        logger.info("correlator shutting down")
        self._running = False

        if self._consumer:
            await self._consumer.stop()
        if self._producer:
            await self._producer.stop()
        if self._redis:
            await self._redis.close()
        if self._pg_pool:
            await self._pg_pool.close()

        logger.info(
            "correlator stopped",
            events_processed=self._metrics.events_processed,
            alerts_generated=self._metrics.alerts_generated,
        )

    # -- Event handler -----------------------------------------------------

    async def _handle_event(
        self, topic: str, key: Optional[str], value: Any,
    ) -> None:
        """Process a single event through all correlation engines."""
        if not isinstance(value, dict):
            logger.warning("non-dict event received, skipping", type=type(value).__name__)
            return

        start_time = time.monotonic()
        all_alerts: list[dict[str, Any]] = []

        try:
            # 1. YAML rule engine
            rule_alerts = await self._rule_engine.match(value)
            all_alerts.extend(rule_alerts)
            self._metrics.rule_alerts += len(rule_alerts)

            # 2. Sliding window rules
            if self._window_rules:
                window_alerts = await self._window_rules.evaluate(value)
                all_alerts.extend(window_alerts)
                self._metrics.window_alerts += len(window_alerts)

            # 3. ML anomaly detection
            if self._ml_detector:
                ml_alert = await self._ml_detector.score(value)
                if ml_alert:
                    all_alerts.append(ml_alert)
                    self._metrics.ml_alerts += 1

        except Exception:
            self._metrics.errors += 1
            logger.exception("correlation error", event_key=key)
            return

        # Publish alerts
        for alert in all_alerts:
            try:
                alert_key = alert.get("username") or alert.get("source_ip") or key
                await self._producer.send_event(
                    OUTPUT_TOPIC,
                    key=alert_key,
                    value=alert,
                )
                logger.info(
                    "alert published",
                    alert_id=alert.get("alert_id"),
                    rule_id=alert.get("rule_id"),
                    severity=alert.get("severity"),
                    title=alert.get("title"),
                )
            except Exception:
                self._metrics.errors += 1
                logger.exception(
                    "failed to publish alert",
                    alert_id=alert.get("alert_id"),
                )

        self._metrics.events_processed += 1
        self._metrics.alerts_generated += len(all_alerts)

        duration_ms = (time.monotonic() - start_time) * 1000
        if all_alerts:
            logger.debug(
                "event correlated",
                alerts=len(all_alerts),
                duration_ms=round(duration_ms, 2),
            )

        self._metrics.log_if_due()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    """Start the correlator service with graceful shutdown handling."""
    service = CorrelatorService()

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
            signal.signal(sig, lambda s, f: _signal_handler())

    # Start service in background task
    service_task = asyncio.create_task(service.start())

    # Wait for shutdown signal
    await shutdown_event.wait()
    await service.stop()

    # Cancel the service task if still running
    if not service_task.done():
        service_task.cancel()
        try:
            await service_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())

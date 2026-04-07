"""
CyberNest Correlation Engine — Consumes parsed events from Kafka,
evaluates rules (Sigma + CyberNest YAML + sliding window),
and publishes alerts to cybernest.alerts topic.
"""

import asyncio
import os
import time
import uuid
from datetime import datetime, timezone

import orjson
import structlog
import redis.asyncio as redis
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from app.engines.rule_engine import load_rules, CompiledRule
from app.engines.window_engine import WindowEngine

logger = structlog.get_logger()

KAFKA_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "correlation-group")
RULES_DIR = os.environ.get("RULES_DIR", "/app/rules")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

INPUT_TOPIC = "cybernest.parsed.events"
OUTPUT_TOPIC = "cybernest.alerts"


class CorrelationEngine:
    def __init__(self, rules: list[CompiledRule], window_engine: WindowEngine):
        self.rules = rules
        self.window_engine = window_engine
        self.stats = {"events": 0, "alerts": 0, "rule_hits": {}}

    async def correlate(self, event: dict) -> list[dict]:
        """Run all correlation against an event, return generated alerts."""
        alerts = []
        self.stats["events"] += 1

        # 1) Static rule evaluation
        for rule in self.rules:
            if rule.evaluate(event):
                alert = {
                    "id": str(uuid.uuid4()),
                    "title": f"[{rule.severity.upper()}] {rule.name}",
                    "description": rule.description,
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "level": rule.level,
                    "source_ip": self._get(event, "source.ip"),
                    "destination_ip": self._get(event, "destination.ip"),
                    "hostname": self._get(event, "host.hostname"),
                    "username": self._get(event, "user.name"),
                    "process_name": self._get(event, "process.name"),
                    "mitre_tactics": rule.mitre_tactics,
                    "mitre_techniques": rule.mitre_techniques,
                    "raw_log": event.get("raw", "")[:1000],
                    "event_timestamp": event.get("@timestamp"),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "alert_type": "rule_match",
                }
                alerts.append(alert)
                self.stats["rule_hits"][rule.id] = self.stats["rule_hits"].get(rule.id, 0) + 1

        # 2) Window-based correlation
        window_alerts = await self.window_engine.process_event(event)
        for wa in window_alerts:
            wa["id"] = str(uuid.uuid4())
            wa["title"] = f"[{wa['severity'].upper()}] {wa['rule_name']}"
            wa["created_at"] = datetime.now(timezone.utc).isoformat()
            wa["alert_type"] = "window_correlation"
            alerts.append(wa)

        self.stats["alerts"] += len(alerts)
        return alerts

    def _get(self, data: dict, dotted_key: str):
        keys = dotted_key.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return current


async def run():
    logger.info("Starting CyberNest Correlation Engine")

    # Load rules
    rules = load_rules(RULES_DIR)
    logger.info("Loaded rules", count=len(rules))

    # Init Redis for window engine
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    window_engine = WindowEngine(redis_client)

    engine = CorrelationEngine(rules, window_engine)

    # Kafka
    consumer = AIOKafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda v: orjson.loads(v),
        auto_offset_reset="latest",
        enable_auto_commit=True,
        max_poll_records=500,
    )

    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: orjson.dumps(v),
        compression_type="lz4",
        linger_ms=5,
    )

    await consumer.start()
    await producer.start()
    logger.info("Correlator consumer and producer started")

    try:
        async for msg in consumer:
            try:
                event = msg.value
                if not event:
                    continue

                alerts = await engine.correlate(event)

                for alert in alerts:
                    await producer.send(
                        OUTPUT_TOPIC,
                        value=alert,
                        key=alert.get("rule_id", "").encode() or None,
                    )

                # Periodic stats
                if engine.stats["events"] % 5000 == 0:
                    logger.info("Correlation stats",
                                events=engine.stats["events"],
                                alerts=engine.stats["alerts"],
                                top_rules=dict(sorted(
                                    engine.stats["rule_hits"].items(),
                                    key=lambda x: x[1], reverse=True
                                )[:5]))

            except Exception as e:
                logger.error("Correlation error", error=str(e))

    except asyncio.CancelledError:
        logger.info("Correlator shutting down")
    finally:
        await consumer.stop()
        await producer.stop()
        await redis_client.aclose()
        logger.info("Correlator stopped", stats=engine.stats)


if __name__ == "__main__":
    asyncio.run(run())

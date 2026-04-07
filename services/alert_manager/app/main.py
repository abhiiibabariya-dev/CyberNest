"""
CyberNest Alert Manager — Consumes alerts from Kafka, deduplicates,
enriches, persists to PostgreSQL, dispatches notifications, and
broadcasts via Redis pub/sub to WebSocket clients.
"""

import asyncio
import os
import uuid
from datetime import datetime, timezone

import orjson
import structlog
import redis.asyncio as redis_lib
from aiokafka import AIOKafkaConsumer
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select

from app.notifications.dispatcher import NotificationDispatcher

logger = structlog.get_logger()

KAFKA_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "alert-group")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
POSTGRES_URL = (
    f"postgresql+asyncpg://{os.environ.get('POSTGRES_USER', 'cybernest')}"
    f":{os.environ.get('POSTGRES_PASSWORD', 'cybernest_secret')}"
    f"@{os.environ.get('POSTGRES_HOST', 'localhost')}"
    f":{os.environ.get('POSTGRES_PORT', '5432')}"
    f"/{os.environ.get('POSTGRES_DB', 'cybernest')}"
)

INPUT_TOPIC = "cybernest.alerts"
WS_CHANNEL = "cybernest:alerts:live"

SEVERITY_MAP = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}


async def run():
    logger.info("Starting CyberNest Alert Manager")

    # DB
    engine = create_async_engine(POSTGRES_URL, pool_size=10)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Redis
    redis_client = redis_lib.from_url(REDIS_URL, decode_responses=True)

    # Notification dispatcher
    notifier = NotificationDispatcher()

    # Kafka
    consumer = AIOKafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda v: orjson.loads(v),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )
    await consumer.start()
    logger.info("Alert Manager consumer started")

    total = 0
    deduplicated = 0

    try:
        async for msg in consumer:
            try:
                alert_data = msg.value
                if not alert_data:
                    continue

                rule_id = alert_data.get("rule_id", "")
                src_ip = alert_data.get("source_ip", "")
                severity = alert_data.get("severity", "medium")

                # 1) Deduplication: same rule + same source within 5 minutes
                dedup_key = f"alert:dedup:{rule_id}:{src_ip}"
                if await redis_client.get(dedup_key):
                    deduplicated += 1
                    # Increment event count on existing alert
                    count_key = f"alert:count:{rule_id}:{src_ip}"
                    await redis_client.incr(count_key)
                    continue

                await redis_client.setex(dedup_key, 300, "1")  # 5 min dedup window

                # 2) Persist to PostgreSQL
                alert_id = str(uuid.uuid4())
                now = datetime.now(timezone.utc)

                async with Session() as session:
                    await session.execute(
                        # Use raw SQL to avoid importing models (separate service)
                        __import__('sqlalchemy').text("""
                            INSERT INTO siem.alerts (
                                id, title, description, severity, status,
                                rule_id, rule_name,
                                source_ip, destination_ip, hostname, username, process_name,
                                mitre_tactics, mitre_techniques,
                                raw_log, event_count, created_at, updated_at
                            ) VALUES (
                                :id, :title, :description, :severity, 'new',
                                :rule_id, :rule_name,
                                :source_ip, :destination_ip, :hostname, :username, :process_name,
                                :mitre_tactics, :mitre_techniques,
                                :raw_log, :event_count, :created_at, :updated_at
                            )
                        """),
                        {
                            "id": alert_id,
                            "title": alert_data.get("title", ""),
                            "description": alert_data.get("description", ""),
                            "severity": severity,
                            "rule_id": rule_id,
                            "rule_name": alert_data.get("rule_name", ""),
                            "source_ip": src_ip,
                            "destination_ip": alert_data.get("destination_ip"),
                            "hostname": alert_data.get("hostname"),
                            "username": alert_data.get("username"),
                            "process_name": alert_data.get("process_name"),
                            "mitre_tactics": alert_data.get("mitre_tactics"),
                            "mitre_techniques": alert_data.get("mitre_techniques"),
                            "raw_log": alert_data.get("raw_log", "")[:2000],
                            "event_count": alert_data.get("event_count", 1),
                            "created_at": now,
                            "updated_at": now,
                        }
                    )
                    await session.commit()

                # 3) Broadcast to WebSocket clients via Redis pub/sub
                ws_payload = {
                    "id": alert_id,
                    "title": alert_data.get("title", ""),
                    "severity": severity,
                    "rule_id": rule_id,
                    "source_ip": src_ip,
                    "hostname": alert_data.get("hostname"),
                    "created_at": now.isoformat(),
                }
                await redis_client.publish(WS_CHANNEL, orjson.dumps(ws_payload).decode())

                # 4) Dispatch notifications for high/critical
                if SEVERITY_MAP.get(severity, 0) >= 3:
                    await notifier.dispatch(alert_data)

                # 5) Update alert counters in Redis
                await redis_client.incr("stats:alerts:total")
                await redis_client.incr(f"stats:alerts:{severity}")

                total += 1
                if total % 100 == 0:
                    logger.info("Alert Manager progress",
                                total=total, deduplicated=deduplicated)

            except Exception as e:
                logger.error("Alert Manager error", error=str(e))

    except asyncio.CancelledError:
        logger.info("Alert Manager shutting down")
    finally:
        await consumer.stop()
        await redis_client.aclose()
        await engine.dispose()
        logger.info("Alert Manager stopped", total=total, deduplicated=deduplicated)


if __name__ == "__main__":
    asyncio.run(run())

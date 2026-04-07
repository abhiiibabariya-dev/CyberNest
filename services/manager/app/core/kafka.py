"""CyberNest Manager — Kafka producer for publishing events to topics."""

import orjson
from aiokafka import AIOKafkaProducer
import structlog

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

_producer: AIOKafkaProducer | None = None


# Topic constants
class Topics:
    RAW_WINDOWS = "cybernest.raw.windows"
    RAW_LINUX = "cybernest.raw.linux"
    RAW_NETWORK = "cybernest.raw.network"
    RAW_CLOUD = "cybernest.raw.cloud"
    RAW_APPLICATION = "cybernest.raw.application"
    RAW_SYSLOG = "cybernest.raw.syslog"
    PARSED_EVENTS = "cybernest.parsed.events"
    ALERTS = "cybernest.alerts"
    CORRELATION = "cybernest.correlation"
    AUDIT = "cybernest.audit"
    AGENT_HEARTBEAT = "cybernest.agent.heartbeat"
    SOAR_ACTIONS = "cybernest.soar.actions"
    THREAT_INTEL = "cybernest.threat_intel"


async def get_kafka_producer() -> AIOKafkaProducer:
    global _producer
    if _producer is None:
        _producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: orjson.dumps(v),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            compression_type="lz4",
            max_batch_size=1048576,
            linger_ms=10,
            acks="all",
        )
        await _producer.start()
        logger.info("Kafka producer started", servers=settings.KAFKA_BOOTSTRAP_SERVERS)
    return _producer


async def publish_event(topic: str, value: dict, key: str | None = None):
    producer = await get_kafka_producer()
    await producer.send(topic, value=value, key=key)


async def close_kafka_producer():
    global _producer
    if _producer:
        await _producer.stop()
        _producer = None
        logger.info("Kafka producer stopped")

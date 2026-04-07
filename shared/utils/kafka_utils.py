"""CyberNest — Kafka producer/consumer helpers with async support.

Provides reusable async Kafka producer and consumer factories used
by all CyberNest microservices (parser, correlator, alert manager, etc.).
"""

from __future__ import annotations
import os
import orjson
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from shared.utils.logger import get_logger

logger = get_logger(__name__)

KAFKA_SERVERS = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")


class Topics:
    """Kafka topic constants — single source of truth for all services."""
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
    DLQ = "cybernest.dlq"


async def create_producer(servers: str | None = None) -> AIOKafkaProducer:
    """Create and start an async Kafka producer with LZ4 compression.

    Returns:
        Started AIOKafkaProducer ready to send messages.
    """
    producer = AIOKafkaProducer(
        bootstrap_servers=servers or KAFKA_SERVERS,
        value_serializer=lambda v: orjson.dumps(v),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        compression_type="lz4",
        max_batch_size=1048576,
        linger_ms=10,
        acks="all",
    )
    await producer.start()
    logger.info("Kafka producer started", extra={"event": "kafka_producer_started"})
    return producer


async def create_consumer(
    *topics: str,
    group_id: str,
    servers: str | None = None,
    auto_offset_reset: str = "latest",
) -> AIOKafkaConsumer:
    """Create and start an async Kafka consumer for the given topics.

    Args:
        *topics: Kafka topic names to subscribe to.
        group_id: Consumer group ID for offset tracking.
        servers: Kafka bootstrap servers override.
        auto_offset_reset: Where to start if no offset exists.

    Returns:
        Started AIOKafkaConsumer ready to iterate messages.
    """
    consumer = AIOKafkaConsumer(
        *topics,
        bootstrap_servers=servers or KAFKA_SERVERS,
        group_id=group_id,
        value_deserializer=lambda v: orjson.loads(v),
        auto_offset_reset=auto_offset_reset,
        enable_auto_commit=True,
        max_poll_records=500,
    )
    await consumer.start()
    logger.info("Kafka consumer started",
                extra={"event": "kafka_consumer_started", "topic": list(topics)})
    return consumer


async def publish(producer: AIOKafkaProducer, topic: str, value: dict, key: str | None = None):
    """Publish a single message to a Kafka topic.

    Args:
        producer: Active Kafka producer instance.
        topic: Target topic name.
        value: Message payload (will be JSON-serialized).
        key: Optional message key for partitioning.
    """
    await producer.send(topic, value=value, key=key)

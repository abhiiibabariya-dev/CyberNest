"""Async Kafka utilities with lazy aiokafka imports."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Awaitable, Callable, Optional

from shared.utils.logger import get_logger

logger = get_logger("kafka")

KAFKA_BOOTSTRAP_SERVERS = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 1.0


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
    DLQ = "cybernest.dlq"


def _json_serializer(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return json.dumps(value, default=str, ensure_ascii=False).encode("utf-8")


def _json_deserializer(raw: bytes) -> Any:
    return json.loads(raw)


def _key_serializer(key: Optional[str]) -> Optional[bytes]:
    return key.encode("utf-8") if key is not None else None


def _key_deserializer(raw: Optional[bytes]) -> Optional[str]:
    return raw.decode("utf-8") if raw is not None else None


def _load_aiokafka():
    try:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
        from aiokafka.errors import KafkaConnectionError, KafkaError, NodeNotReadyError
        return AIOKafkaConsumer, AIOKafkaProducer, KafkaConnectionError, KafkaError, NodeNotReadyError
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "aiokafka is not installed. Install the relevant service requirements before using Kafka helpers."
        ) from exc


class KafkaProducerManager:
    _instances: dict[str, 'KafkaProducerManager'] = {}

    def __new__(cls, bootstrap_servers: Optional[str] = None) -> 'KafkaProducerManager':
        servers = bootstrap_servers or KAFKA_BOOTSTRAP_SERVERS
        if servers not in cls._instances:
            instance = super().__new__(cls)
            instance._initialized = False
            cls._instances[servers] = instance
        return cls._instances[servers]

    def __init__(self, bootstrap_servers: Optional[str] = None) -> None:
        if getattr(self, '_initialized', False):
            return
        self._bootstrap_servers = bootstrap_servers or KAFKA_BOOTSTRAP_SERVERS
        self._producer: Any = None
        self._started = False
        self._initialized = True

    async def start(self) -> None:
        if self._started and self._producer is not None:
            return

        _, AIOKafkaProducer, KafkaConnectionError, KafkaError, NodeNotReadyError = _load_aiokafka()
        last_error: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._producer = AIOKafkaProducer(
                    bootstrap_servers=self._bootstrap_servers,
                    value_serializer=_json_serializer,
                    key_serializer=_key_serializer,
                    compression_type="lz4",
                    max_batch_size=1_048_576,
                    linger_ms=10,
                    acks="all",
                    retry_backoff_ms=500,
                    request_timeout_ms=30_000,
                )
                await self._producer.start()
                self._started = True
                logger.info("kafka producer started", servers=self._bootstrap_servers, attempt=attempt)
                return
            except (KafkaConnectionError, NodeNotReadyError, KafkaError) as exc:
                last_error = exc
                wait = RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning("kafka producer connection failed", attempt=attempt, wait_seconds=wait, error=str(exc))
                await asyncio.sleep(wait)
        raise ConnectionError(f"Failed to connect Kafka producer to {self._bootstrap_servers}: {last_error}")

    async def stop(self) -> None:
        if self._producer is not None and self._started:
            await self._producer.stop()
            self._producer = None
            self._started = False
            self._instances.pop(self._bootstrap_servers, None)
            logger.info("kafka producer stopped", servers=self._bootstrap_servers)

    async def send_event(self, topic: str, key: Optional[str], value: Any) -> None:
        if not self._started or self._producer is None:
            raise ConnectionError("Kafka producer is not started. Call start() first.")
        last_error: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                await self._producer.send_and_wait(topic, key=key, value=value)
                return
            except Exception as exc:
                last_error = exc
                wait = RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning("kafka send failed", topic=topic, attempt=attempt, error=str(exc))
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(wait)
        raise RuntimeError(f"Failed to publish event to {topic}: {last_error}")

    @property
    def is_started(self) -> bool:
        return self._started


class KafkaConsumerManager:
    def __init__(self, bootstrap_servers: Optional[str] = None) -> None:
        self._bootstrap_servers = bootstrap_servers or KAFKA_BOOTSTRAP_SERVERS
        self._consumer: Any = None
        self._running = False

    async def consume(
        self,
        topics: list[str],
        group_id: str,
        handler: Callable[[str, Optional[str], Any], Awaitable[None]],
        auto_offset_reset: str = "latest",
        max_poll_records: int = 500,
    ) -> None:
        AIOKafkaConsumer, _, KafkaConnectionError, KafkaError, NodeNotReadyError = _load_aiokafka()
        last_error: Optional[Exception] = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._consumer = AIOKafkaConsumer(
                    *topics,
                    bootstrap_servers=self._bootstrap_servers,
                    group_id=group_id,
                    value_deserializer=_json_deserializer,
                    key_deserializer=_key_deserializer,
                    auto_offset_reset=auto_offset_reset,
                    enable_auto_commit=False,
                    max_poll_records=max_poll_records,
                )
                await self._consumer.start()
                break
            except (KafkaConnectionError, NodeNotReadyError, KafkaError) as exc:
                last_error = exc
                wait = RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning("kafka consumer connection failed", attempt=attempt, wait_seconds=wait, error=str(exc))
                await asyncio.sleep(wait)
        else:
            raise ConnectionError(f"Failed to connect Kafka consumer to {self._bootstrap_servers}: {last_error}")

        self._running = True
        try:
            async for message in self._consumer:
                try:
                    await handler(message.topic, message.key, message.value)
                finally:
                    await self._consumer.commit()
        finally:
            self._running = False
            await self.stop()

    async def stop(self) -> None:
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None
            logger.info("kafka consumer stopped")

    @property
    def is_running(self) -> bool:
        return self._running


async def create_producer(servers: Optional[str] = None):
    _, AIOKafkaProducer, _, _, _ = _load_aiokafka()
    producer = AIOKafkaProducer(
        bootstrap_servers=servers or KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=_json_serializer,
        key_serializer=_key_serializer,
        compression_type="lz4",
        max_batch_size=1_048_576,
        linger_ms=10,
        acks="all",
    )
    await producer.start()
    return producer


async def create_consumer(*topics: str, group_id: str, servers: Optional[str] = None, auto_offset_reset: str = "latest"):
    AIOKafkaConsumer, _, _, _, _ = _load_aiokafka()
    consumer = AIOKafkaConsumer(
        *topics,
        bootstrap_servers=servers or KAFKA_BOOTSTRAP_SERVERS,
        group_id=group_id,
        value_deserializer=_json_deserializer,
        key_deserializer=_key_deserializer,
        auto_offset_reset=auto_offset_reset,
        enable_auto_commit=True,
        max_poll_records=500,
    )
    await consumer.start()
    return consumer


async def publish(producer: Any, topic: str, value: dict[str, Any], key: Optional[str] = None) -> None:
    await producer.send(topic, value=value, key=key)

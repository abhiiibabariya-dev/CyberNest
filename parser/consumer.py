"""
CyberNest Parser Service — Main Consumer.

Consumes raw log events from Kafka cybernest.raw.* topics, auto-detects
the log format, routes to the correct parser, runs all enrichers,
validates against ECS, and publishes to cybernest.parsed.events.
Failed events go to cybernest.dead.letter.

Run with: python -m parser.consumer
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils.logger import get_logger
from shared.utils.kafka_utils import (
    KafkaConsumerManager,
    KafkaProducerManager,
    Topics,
)
from shared.models.event import ECSEventDocument

from parser.parsers import detect_parser, get_parser, list_parsers
from parser.enrichers.geoip import GeoIPEnricher
from parser.enrichers.threat_intel import ThreatIntelEnricher
from parser.enrichers.asset_lookup import AssetLookupEnricher

logger = get_logger("parser.consumer")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONSUMER_GROUP = os.environ.get("PARSER_CONSUMER_GROUP", "parser-group")
RAW_TOPICS = [
    Topics.RAW_WINDOWS,
    Topics.RAW_LINUX,
    Topics.RAW_NETWORK,
    Topics.RAW_CLOUD,
    Topics.RAW_APPLICATION,
    Topics.RAW_SYSLOG,
]
OUTPUT_TOPIC = Topics.PARSED_EVENTS
DLQ_TOPIC = Topics.DLQ

# Metrics
_metrics = {
    "total_received": 0,
    "total_parsed": 0,
    "total_enriched": 0,
    "total_published": 0,
    "total_errors": 0,
    "parse_errors": 0,
    "enrich_errors": 0,
    "validation_errors": 0,
    "dlq_published": 0,
    "by_parser": {},
    "by_topic": {},
    "last_metrics_log": 0.0,
}

METRICS_LOG_INTERVAL = float(os.environ.get("METRICS_LOG_INTERVAL", "60"))


# ---------------------------------------------------------------------------
# Format detection and topic-based hints
# ---------------------------------------------------------------------------

TOPIC_PARSER_HINTS: dict[str, list[str]] = {
    Topics.RAW_WINDOWS: ["windows_evtx"],
    Topics.RAW_LINUX: ["auditd", "syslog"],
    Topics.RAW_NETWORK: ["suricata_eve", "zeek", "cisco_asa", "palo_alto", "fortinet", "cef", "leef"],
    Topics.RAW_CLOUD: ["aws_cloudtrail", "json"],
    Topics.RAW_APPLICATION: ["json", "syslog"],
    Topics.RAW_SYSLOG: ["syslog", "cef", "leef", "cisco_asa", "palo_alto", "fortinet"],
}


def _detect_format(topic: str, raw_data: Any) -> Optional[str]:
    """Detect log format using auto-detection, with topic hints as fallback."""
    # Try auto-detection first (uses registered detector functions)
    detected = detect_parser(raw_data)
    if detected:
        return detected

    # Use topic hints to try specific parsers
    hints = TOPIC_PARSER_HINTS.get(topic, [])
    for parser_name in hints:
        parser_func = get_parser(parser_name)
        if parser_func:
            try:
                # Try parsing — if it succeeds, this is the right parser
                parser_func(raw_data)
                return parser_name
            except Exception:
                continue

    # Final fallback: JSON parser (accepts anything)
    return "json"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_ecs(event: dict[str, Any]) -> bool:
    """Validate that the parsed event has minimum required ECS fields."""
    if not event:
        return False
    if not event.get("@timestamp") and not event.get("timestamp"):
        return False
    if not event.get("event"):
        return False
    return True


def _ensure_ecs_fields(event: dict[str, Any]) -> dict[str, Any]:
    """Ensure minimum ECS fields are present."""
    # Ensure @timestamp
    if not event.get("@timestamp"):
        event["@timestamp"] = datetime.now(timezone.utc).isoformat()

    # Ensure event.kind
    event_meta = event.setdefault("event", {})
    if not event_meta.get("kind"):
        event_meta["kind"] = "event"

    # Ensure event.module
    if not event_meta.get("module"):
        event_meta["module"] = "unknown"

    # Ensure ecs.version
    event.setdefault("ecs", {}).setdefault("version", "8.11.0")

    return event


# ---------------------------------------------------------------------------
# Main handler
# ---------------------------------------------------------------------------

class ParserService:
    """Main parser service orchestrator."""

    def __init__(self) -> None:
        self._consumer = KafkaConsumerManager()
        self._producer = KafkaProducerManager()
        self._geoip = GeoIPEnricher()
        self._threat_intel = ThreatIntelEnricher()
        self._asset_lookup = AssetLookupEnricher()
        self._running = False

    async def start(self) -> None:
        """Initialize all components and start consuming."""
        logger.info("parser service starting")

        # Start Kafka producer
        await self._producer.start()

        # Initialize enrichers (non-blocking — they handle failures gracefully)
        enricher_tasks = [
            self._geoip.initialize(),
            self._threat_intel.initialize(),
            self._asset_lookup.initialize(),
        ]
        results = await asyncio.gather(*enricher_tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                names = ["geoip", "threat_intel", "asset_lookup"]
                logger.warning(
                    "enricher initialization failed",
                    enricher=names[i],
                    error=str(result),
                )

        # Log registered parsers
        parsers = list_parsers()
        logger.info("parsers registered", parsers=parsers, count=len(parsers))

        # Start consuming
        self._running = True
        logger.info(
            "parser consumer starting",
            topics=RAW_TOPICS,
            group=CONSUMER_GROUP,
        )
        await self._consumer.consume(
            topics=RAW_TOPICS,
            group_id=CONSUMER_GROUP,
            handler=self._handle_message,
            auto_offset_reset="latest",
            max_poll_records=500,
        )

    async def stop(self) -> None:
        """Gracefully shut down all components."""
        self._running = False
        logger.info("parser service stopping")

        await self._consumer.stop()
        await self._producer.stop()
        await self._geoip.close()
        await self._threat_intel.close()
        await self._asset_lookup.close()

        # Log final metrics
        self._log_metrics(force=True)
        logger.info("parser service stopped")

    async def _handle_message(
        self,
        topic: str,
        key: Optional[str],
        value: Any,
    ) -> None:
        """Process a single raw log message from Kafka.

        1. Detect format
        2. Parse to ECS
        3. Run enrichers
        4. Validate
        5. Publish to parsed topic (or DLQ on failure)
        """
        start_time = time.monotonic()
        _metrics["total_received"] += 1
        _metrics["by_topic"][topic] = _metrics["by_topic"].get(topic, 0) + 1

        raw_data = value
        event_id = uuid4().hex

        try:
            # Step 1: Detect format
            parser_name = _detect_format(topic, raw_data)
            if not parser_name:
                raise ValueError(f"Could not detect log format for topic={topic}")

            # Step 2: Parse
            parser_func = get_parser(parser_name)
            if not parser_func:
                raise ValueError(f"Parser '{parser_name}' not found")

            parsed = parser_func(raw_data)
            if not parsed:
                raise ValueError(f"Parser '{parser_name}' returned empty result")

            _metrics["total_parsed"] += 1
            _metrics["by_parser"][parser_name] = _metrics["by_parser"].get(parser_name, 0) + 1

            # Step 3: Enrich
            try:
                parsed = await self._geoip.enrich_event(parsed)
                parsed = await self._threat_intel.enrich_event(parsed)
                parsed = await self._asset_lookup.enrich_event(parsed)
                _metrics["total_enriched"] += 1
            except Exception as enrich_exc:
                _metrics["enrich_errors"] += 1
                logger.warning(
                    "enrichment failed, continuing with parsed event",
                    event_id=event_id,
                    error=str(enrich_exc),
                )

            # Step 4: Ensure minimum ECS fields
            parsed = _ensure_ecs_fields(parsed)

            # Add CyberNest pipeline metadata
            parse_duration = (time.monotonic() - start_time) * 1000
            cn_meta = parsed.setdefault("cybernest", {})
            cn_meta["event_id"] = event_id
            cn_meta["parse_time"] = datetime.now(timezone.utc).isoformat()
            cn_meta["parse_duration_ms"] = round(parse_duration, 2)
            cn_meta["ingested_at"] = datetime.now(timezone.utc).isoformat()
            cn_meta["source_topic"] = topic

            # Step 5: Validate
            if not _validate_ecs(parsed):
                _metrics["validation_errors"] += 1
                logger.warning(
                    "ECS validation failed",
                    event_id=event_id,
                    parser=parser_name,
                )
                # Still publish but tag as validation-failed
                parsed.setdefault("tags", []).append("validation-failed")

            # Step 6: Publish
            await self._producer.send_event(
                topic=OUTPUT_TOPIC,
                key=key,
                value=parsed,
            )
            _metrics["total_published"] += 1

        except Exception as exc:
            _metrics["total_errors"] += 1
            _metrics["parse_errors"] += 1
            parse_duration = (time.monotonic() - start_time) * 1000

            logger.error(
                "parse failed, sending to DLQ",
                event_id=event_id,
                topic=topic,
                error=str(exc),
                duration_ms=round(parse_duration, 2),
            )

            # Send to Dead Letter Queue
            try:
                dlq_event = {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": {
                        "kind": "pipeline_error",
                        "module": "parser",
                        "action": "parse-failed",
                        "outcome": "failure",
                    },
                    "error": {
                        "message": str(exc),
                        "stack_trace": traceback.format_exc(),
                        "type": type(exc).__name__,
                    },
                    "cybernest": {
                        "event_id": event_id,
                        "parser_name": "unknown",
                        "parse_status": "error",
                        "parse_duration_ms": round(parse_duration, 2),
                        "source_topic": topic,
                        "ingested_at": datetime.now(timezone.utc).isoformat(),
                    },
                    "raw": json.dumps(raw_data, default=str)[:10000] if raw_data else None,
                    "tags": ["parse-error", "dead-letter"],
                }
                await self._producer.send_event(
                    topic=DLQ_TOPIC,
                    key=key,
                    value=dlq_event,
                )
                _metrics["dlq_published"] += 1
            except Exception as dlq_exc:
                logger.error(
                    "DLQ publish failed",
                    event_id=event_id,
                    error=str(dlq_exc),
                )

        # Periodic metrics logging
        self._log_metrics()

    def _log_metrics(self, force: bool = False) -> None:
        """Log parsing metrics periodically."""
        now = time.time()
        if not force and now - _metrics["last_metrics_log"] < METRICS_LOG_INTERVAL:
            return

        _metrics["last_metrics_log"] = now
        logger.info(
            "parser metrics",
            received=_metrics["total_received"],
            parsed=_metrics["total_parsed"],
            enriched=_metrics["total_enriched"],
            published=_metrics["total_published"],
            errors=_metrics["total_errors"],
            parse_errors=_metrics["parse_errors"],
            enrich_errors=_metrics["enrich_errors"],
            validation_errors=_metrics["validation_errors"],
            dlq=_metrics["dlq_published"],
            by_parser=_metrics["by_parser"],
            by_topic=_metrics["by_topic"],
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    """Run the parser service."""
    service = ParserService()

    # Handle graceful shutdown
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _signal_handler() -> None:
        logger.info("shutdown signal received")
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            signal.signal(sig, lambda s, f: _signal_handler())

    # Start service in background
    consume_task = asyncio.create_task(service.start())

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Graceful shutdown
    consume_task.cancel()
    try:
        await consume_task
    except asyncio.CancelledError:
        pass

    await service.stop()


if __name__ == "__main__":
    asyncio.run(main())

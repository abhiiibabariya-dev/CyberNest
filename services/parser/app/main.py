"""
CyberNest Parser Service — Kafka consumer that parses raw logs,
normalizes to ECS, enriches with GeoIP/threat intel, and publishes
to cybernest.parsed.events topic.
"""

import asyncio
import os
import time

import orjson
import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from app.parsers.syslog import SyslogParser
from app.parsers.cef import CEFParser
from app.parsers.leef import LEEFParser
from app.parsers.windows import WindowsEventParser
from app.parsers.json_parser import JSONParser
from app.parsers.firewall import PaloAltoParser, CiscoASAParser, FortiGateParser
from app.parsers.linux import LinuxAuthParser, AuditdParser, WebAccessLogParser
from app.enrichment.geoip import init_geoip, enrich_event

logger = structlog.get_logger()

# All parsers in priority order
PARSERS = [
    WindowsEventParser(),
    CEFParser(),
    LEEFParser(),
    PaloAltoParser(),
    CiscoASAParser(),
    FortiGateParser(),
    AuditdParser(),
    LinuxAuthParser(),
    WebAccessLogParser(),
    SyslogParser(),
    JSONParser(),  # JSON last as catch-all
]

# Raw topics to consume
RAW_TOPICS = [
    "cybernest.raw.windows",
    "cybernest.raw.linux",
    "cybernest.raw.network",
    "cybernest.raw.cloud",
    "cybernest.raw.application",
    "cybernest.raw.syslog",
]

PARSED_TOPIC = "cybernest.parsed.events"

KAFKA_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "parser-group")


async def parse_raw_log(raw: str, metadata: dict | None = None) -> dict | None:
    """Try each parser until one matches, return ECS event dict."""
    for parser in PARSERS:
        try:
            if parser.can_parse(raw):
                event = parser.parse(raw, metadata)
                if event:
                    result = event.build()
                    result["cybernest"]["parser_name"] = parser.name
                    return result
        except Exception as e:
            logger.error("Parser error", parser=parser.name, error=str(e))
            continue

    # Fallback: unparseable log
    return {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "raw": raw,
        "event": {"module": "unknown", "category": "unknown"},
        "cybernest": {
            "parse_status": "unparseable",
            "parser_name": "none",
        },
    }


async def run():
    logger.info("Starting CyberNest Parser Service", topics=RAW_TOPICS)

    # Init enrichment
    init_geoip()

    consumer = AIOKafkaConsumer(
        *RAW_TOPICS,
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
    logger.info("Parser consumer and producer started")

    parsed_count = 0
    error_count = 0

    try:
        async for msg in consumer:
            try:
                raw_data = msg.value
                raw_log = raw_data.get("raw", "")
                if not raw_log:
                    continue

                start = time.monotonic()

                # Parse
                parsed = await parse_raw_log(raw_log, raw_data)
                if not parsed:
                    error_count += 1
                    continue

                # Inject metadata from raw message
                if raw_data.get("agent_id"):
                    parsed.setdefault("agent", {})["id"] = raw_data["agent_id"]
                if raw_data.get("source"):
                    parsed.setdefault("cybernest", {})["source_name"] = raw_data["source"]
                if raw_data.get("tags"):
                    parsed["tags"] = raw_data["tags"]

                # Enrich with GeoIP
                parsed = enrich_event(parsed)

                # Add parse timing
                elapsed_ms = (time.monotonic() - start) * 1000
                parsed.setdefault("cybernest", {})["parse_duration_ms"] = round(elapsed_ms, 2)

                # Publish to parsed topic
                await producer.send(
                    PARSED_TOPIC,
                    value=parsed,
                    key=parsed.get("cybernest", {}).get("event_id", "").encode() or None,
                )
                parsed_count += 1

                if parsed_count % 1000 == 0:
                    logger.info("Parse progress",
                                parsed=parsed_count,
                                errors=error_count,
                                rate=f"{1000 / (time.monotonic() - start):.0f} eps")

            except Exception as e:
                error_count += 1
                logger.error("Failed to process message", error=str(e), topic=msg.topic)

    except asyncio.CancelledError:
        logger.info("Parser shutting down")
    finally:
        await consumer.stop()
        await producer.stop()
        logger.info("Parser stopped", total_parsed=parsed_count, total_errors=error_count)


if __name__ == "__main__":
    asyncio.run(run())

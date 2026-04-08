"""
CyberNest Manager -- Syslog Receiver.

Async UDP (port 514) and TCP (port 601) syslog receivers that parse
RFC 3164 and RFC 5424 messages and publish to Kafka.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from manager.config import get_settings
from shared.utils.kafka_utils import KafkaProducerManager, Topics
from shared.utils.logger import get_logger

logger = get_logger("manager.syslog_receiver")
settings = get_settings()

# ---------------------------------------------------------------------------
# RFC 3164 Parser (BSD syslog)
# Format: <PRI>TIMESTAMP HOSTNAME APP-NAME[PID]: MESSAGE
# ---------------------------------------------------------------------------

_RFC3164_PATTERN = re.compile(
    r"<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(.+)"
)

# RFC 5424 Parser
# Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424_PATTERN = re.compile(
    r"<(\d{1,3})>"
    r"(\d{1,2})\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\[.*?\]|-)\s*"
    r"(.*)$",
    re.DOTALL,
)

# Syslog severity levels
SEVERITY_MAP = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

# Syslog facility codes
FACILITY_MAP = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "cron2",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}


def parse_syslog_message(raw: str, source_ip: str = "0.0.0.0") -> dict:
    """Parse a syslog message (RFC 3164 or RFC 5424) into an ECS-compatible event."""
    event_id = uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    base_event = {
        "@timestamp": now,
        "message": raw.strip(),
        "event": {
            "kind": "event",
            "module": "syslog",
            "dataset": "syslog.raw",
        },
        "source": {"ip": source_ip},
        "log": {"syslog": {}},
        "cybernest": {
            "event_id": event_id,
            "source_name": "syslog",
            "ingested_at": now,
        },
        "raw": raw.strip(),
    }

    # Try RFC 5424 first
    match = _RFC5424_PATTERN.match(raw.strip())
    if match:
        pri = int(match.group(1))
        version = match.group(2)
        timestamp = match.group(3)
        hostname = match.group(4)
        app_name = match.group(5)
        proc_id = match.group(6)
        msg_id = match.group(7)
        structured_data = match.group(8)
        message = match.group(9)

        facility = pri >> 3
        severity = pri & 0x07

        base_event["log"]["syslog"] = {
            "priority": pri,
            "facility": {"code": facility, "name": FACILITY_MAP.get(facility, str(facility))},
            "severity": {"code": severity, "name": SEVERITY_MAP.get(severity, str(severity))},
            "version": version,
            "msgid": msg_id if msg_id != "-" else None,
            "structured_data": structured_data if structured_data != "-" else None,
        }
        base_event["host"] = {"hostname": hostname if hostname != "-" else None}
        base_event["process"] = {
            "name": app_name if app_name != "-" else None,
            "pid": int(proc_id) if proc_id != "-" and proc_id.isdigit() else None,
        }
        base_event["message"] = message.strip() if message else raw.strip()

        # Try to parse ISO timestamp
        if timestamp != "-":
            try:
                ts = timestamp.replace("Z", "+00:00")
                base_event["@timestamp"] = datetime.fromisoformat(ts).isoformat()
            except (ValueError, TypeError):
                pass

        base_event["event"]["dataset"] = "syslog.rfc5424"
        return base_event

    # Try RFC 3164
    match = _RFC3164_PATTERN.match(raw.strip())
    if match:
        pri = int(match.group(1))
        timestamp = match.group(2)
        hostname = match.group(3)
        content = match.group(4)

        facility = pri >> 3
        severity = pri & 0x07

        base_event["log"]["syslog"] = {
            "priority": pri,
            "facility": {"code": facility, "name": FACILITY_MAP.get(facility, str(facility))},
            "severity": {"code": severity, "name": SEVERITY_MAP.get(severity, str(severity))},
        }
        base_event["host"] = {"hostname": hostname}
        base_event["message"] = content.strip()

        # Parse BSD-style timestamp (no year)
        try:
            current_year = datetime.now().year
            ts = datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
            ts = ts.replace(tzinfo=timezone.utc)
            base_event["@timestamp"] = ts.isoformat()
        except (ValueError, TypeError):
            pass

        # Try to extract app name and PID from content
        app_match = re.match(r"(\S+?)(?:\[(\d+)\])?:\s*(.*)", content)
        if app_match:
            base_event["process"] = {
                "name": app_match.group(1),
                "pid": int(app_match.group(2)) if app_match.group(2) else None,
            }
            base_event["message"] = app_match.group(3)

        base_event["event"]["dataset"] = "syslog.rfc3164"
        return base_event

    # Unparseable -- return raw
    base_event["event"]["dataset"] = "syslog.raw"
    base_event["tags"] = ["_syslog_parse_failure"]
    return base_event


# ---------------------------------------------------------------------------
# UDP Receiver
# ---------------------------------------------------------------------------

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol handler for syslog messages."""

    def __init__(self, kafka_producer: KafkaProducerManager):
        self._producer = kafka_producer
        self._loop = asyncio.get_event_loop()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip = addr[0]
        try:
            raw = data.decode("utf-8", errors="replace").strip()
            if not raw:
                return

            event = parse_syslog_message(raw, source_ip=source_ip)

            # Schedule async send
            asyncio.ensure_future(
                self._send_to_kafka(event, source_ip),
                loop=self._loop,
            )
        except Exception as exc:
            logger.error("syslog UDP parse error", error=str(exc), source=source_ip)

    async def _send_to_kafka(self, event: dict, source_ip: str) -> None:
        if self._producer.is_started:
            try:
                await self._producer.send_event(
                    topic=Topics.RAW_SYSLOG,
                    key=source_ip,
                    value=event,
                )
            except Exception as exc:
                logger.error("failed to send syslog event to kafka", error=str(exc))

    def error_received(self, exc: Exception) -> None:
        logger.error("syslog UDP error", error=str(exc))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.warning("syslog UDP connection lost", error=str(exc))


# ---------------------------------------------------------------------------
# TCP Receiver
# ---------------------------------------------------------------------------

async def handle_syslog_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    kafka_producer: KafkaProducerManager,
) -> None:
    """Handle a single TCP syslog client connection."""
    addr = writer.get_extra_info("peername")
    source_ip = addr[0] if addr else "0.0.0.0"

    logger.debug("syslog TCP connection from", source=source_ip)

    try:
        while True:
            # Syslog over TCP: messages are newline-delimited or length-prefixed
            data = await reader.readline()
            if not data:
                break

            raw = data.decode("utf-8", errors="replace").strip()
            if not raw:
                continue

            event = parse_syslog_message(raw, source_ip=source_ip)

            if kafka_producer.is_started:
                try:
                    await kafka_producer.send_event(
                        topic=Topics.RAW_SYSLOG,
                        key=source_ip,
                        value=event,
                    )
                except Exception as exc:
                    logger.error("failed to send syslog TCP event", error=str(exc))

    except asyncio.IncompleteReadError:
        pass
    except ConnectionResetError:
        pass
    except Exception as exc:
        logger.error("syslog TCP client error", source=source_ip, error=str(exc))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_syslog_receiver() -> tuple:
    """Start both UDP and TCP syslog receivers. Returns (udp_transport, tcp_server)."""
    kafka_producer = KafkaProducerManager(settings.KAFKA_BOOTSTRAP)
    try:
        await kafka_producer.start()
    except Exception as exc:
        logger.error("failed to start kafka producer for syslog", error=str(exc))

    loop = asyncio.get_event_loop()

    # UDP receiver
    udp_transport = None
    try:
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(kafka_producer),
            local_addr=("0.0.0.0", settings.SYSLOG_UDP_PORT),
        )
        logger.info("syslog UDP receiver started", port=settings.SYSLOG_UDP_PORT)
    except Exception as exc:
        logger.error("failed to start syslog UDP", error=str(exc), port=settings.SYSLOG_UDP_PORT)

    # TCP receiver
    tcp_server = None
    try:
        tcp_server = await asyncio.start_server(
            lambda r, w: handle_syslog_tcp_client(r, w, kafka_producer),
            "0.0.0.0",
            settings.SYSLOG_TCP_PORT,
        )
        logger.info("syslog TCP receiver started", port=settings.SYSLOG_TCP_PORT)
    except Exception as exc:
        logger.error("failed to start syslog TCP", error=str(exc), port=settings.SYSLOG_TCP_PORT)

    return udp_transport, tcp_server

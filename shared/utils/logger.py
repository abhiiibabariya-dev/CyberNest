"""
CyberNest Structured JSON Logger.

Uses structlog to produce JSON-formatted log output suitable for
aggregation by Docker, Kubernetes, or any log shipper.

Usage:
    from shared.utils.logger import get_logger
    logger = get_logger("parser")
    logger.info("event parsed", event_id="abc123", duration_ms=12.5)
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

import structlog


def _add_timestamp(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add ISO 8601 UTC timestamp to every log entry."""
    event_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    return event_dict


def _add_log_level(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Add the log level to the event dict."""
    event_dict["level"] = method_name.upper()
    return event_dict


def _add_service_name(service_name: str):
    """Return a processor that injects the service name."""

    def processor(
        logger: Any, method_name: str, event_dict: dict[str, Any]
    ) -> dict[str, Any]:
        event_dict["service"] = service_name
        return event_dict

    return processor


def _configure_structlog(service_name: str) -> None:
    """Configure structlog with JSON renderer and standard processors.

    This is idempotent; calling it multiple times with the same service name
    will not create duplicate processors.
    """
    log_level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Configure stdlib logging as the backend
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        _add_timestamp,
        _add_log_level,
        _add_service_name(service_name),
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Also configure a ProcessorFormatter so stdlib loggers produce JSON
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )

    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)


# Track whether structlog has been configured to avoid duplicate setup
_configured_service: str | None = None


def get_logger(service_name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured JSON logger bound with the given service name.

    Args:
        service_name: Name of the microservice (e.g. "parser", "correlator",
                      "alert_manager", "manager", "indexer").

    Returns:
        A structlog BoundLogger that outputs JSON to stdout with fields:
        timestamp, level, service, logger, event (message), plus any
        extra key-value pairs passed at log time.

    Example:
        logger = get_logger("correlator")
        logger.info("rule matched", rule_id="R001", severity="high")
        # -> {"timestamp":"2025-...","level":"INFO","service":"correlator",
        #     "logger":"correlator","event":"rule matched","rule_id":"R001",
        #     "severity":"high"}
    """
    global _configured_service

    if _configured_service != service_name:
        _configure_structlog(service_name)
        _configured_service = service_name

    return structlog.get_logger(service_name)

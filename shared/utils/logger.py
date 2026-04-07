"""CyberNest — Structured JSON logger for all services.

Every service logs to stdout as JSON for easy aggregation by Docker/K8s.
Fields: timestamp, level, service, message, plus arbitrary context.
"""

import logging
import json
import sys
import os
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def __init__(self, service_name: str = "cybernest"):
        super().__init__()
        self.service = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include extra fields passed via logger.info("msg", extra={...})
        for key in ("event", "error", "duration_ms", "count", "ip",
                     "user", "rule_id", "alert_id", "agent_id", "topic"):
            val = getattr(record, key, None)
            if val is not None:
                log_entry[key] = val

        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
            log_entry["traceback"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def get_logger(name: str, service_name: str | None = None) -> logging.Logger:
    """Create a structured JSON logger.

    Args:
        name: Logger name (typically __name__).
        service_name: Override the service name in log output.

    Returns:
        Configured logger that writes JSON to stdout.
    """
    svc = service_name or os.environ.get("SERVICE_NAME", "cybernest")
    level = os.environ.get("LOG_LEVEL", "INFO").upper()

    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter(svc))
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level, logging.INFO))
    return logger

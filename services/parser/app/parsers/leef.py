"""CyberNest Parser — LEEF (Log Event Extended Format / IBM QRadar) parser."""

import re
from app.parsers.base import BaseParser, ECSEvent

# LEEF format: LEEF:Version|Vendor|Product|Version|EventID|<delim>key=value pairs
LEEF_HEADER_RE = re.compile(
    r"^LEEF:(\d+(?:\.\d+)?)\|"
    r"([^|]*)\|"    # vendor
    r"([^|]*)\|"    # product
    r"([^|]*)\|"    # version
    r"([^|]*)\|"    # event id
    r"(.*)$",
    re.DOTALL,
)

# LEEF → ECS field mapping
LEEF_FIELD_MAP = {
    "src": "source.ip",
    "dst": "destination.ip",
    "srcPort": "source.port",
    "dstPort": "destination.port",
    "usrName": "user.name",
    "proto": "network.protocol",
    "srcBytes": "network.bytes_in",
    "dstBytes": "network.bytes_out",
    "action": "event.action",
    "policy": "rule.name",
    "resource": "url.original",
    "url": "url.original",
    "devTime": "@timestamp",
    "devTimeFormat": "cybernest.leef.time_format",
    "sev": "event.severity",
    "cat": "event.category",
    "identSrc": "source.domain",
    "identHostName": "host.hostname",
}


class LEEFParser(BaseParser):
    name = "leef"
    supported_formats = ["leef"]

    def can_parse(self, raw: str) -> bool:
        return raw.startswith("LEEF:")

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        m = LEEF_HEADER_RE.match(raw)
        if not m:
            return None

        event = ECSEvent().set_raw(raw)

        version = m.group(1)
        vendor = m.group(2)
        product = m.group(3)
        dev_version = m.group(4)
        event_id = m.group(5)
        extensions = m.group(6)

        event.set_field("observer.vendor", vendor)
        event.set_field("observer.product", product)
        event.set_field("observer.version", dev_version)
        event.set_event(module="leef", category=vendor.lower(), action=event_id)
        event.set_field("cybernest.leef.version", version)

        # Determine delimiter (LEEF 2.0 allows custom, default is tab)
        delimiter = "\t"
        if version.startswith("2") and extensions and len(extensions) > 0:
            delimiter = extensions[0]
            extensions = extensions[1:]

        # Parse key=value pairs
        for pair in extensions.split(delimiter):
            if "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            key = key.strip()
            value = value.strip()

            ecs_field = LEEF_FIELD_MAP.get(key)
            if ecs_field:
                if ecs_field == "@timestamp":
                    event.set_timestamp(value)
                elif "port" in ecs_field or "bytes" in ecs_field or ecs_field == "event.severity":
                    try:
                        event.set_field(ecs_field, int(value))
                    except ValueError:
                        event.set_field(ecs_field, value)
                else:
                    event.set_field(ecs_field, value)
            else:
                event.set_field(f"cybernest.leef.{key}", value)

        return event

"""CyberNest Parser — CEF (Common Event Format) parser."""

import re
from app.parsers.base import BaseParser, ECSEvent

# CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
CEF_HEADER_RE = re.compile(
    r"^(?:.*\s)?CEF:(\d+)\|"
    r"([^|]*)\|"    # vendor
    r"([^|]*)\|"    # product
    r"([^|]*)\|"    # device version
    r"([^|]*)\|"    # signature id
    r"([^|]*)\|"    # name
    r"([^|]*)\|"    # severity
    r"(.*)$",       # extensions
    re.DOTALL,
)

# CEF extension key=value parsing
CEF_EXT_RE = re.compile(r"(\w+)=((?:[^\\= ]|\\[= \\])*(?:\s+(?!\w+=)(?:[^\\= ]|\\[= \\])*)*)")

# CEF → ECS field mapping
CEF_FIELD_MAP = {
    "src": "source.ip",
    "dst": "destination.ip",
    "spt": "source.port",
    "dpt": "destination.port",
    "suser": "user.name",
    "duser": "user.target.name",
    "sproc": "process.name",
    "dproc": "process.parent.name",
    "fname": "file.name",
    "fsize": "file.size",
    "request": "url.original",
    "requestMethod": "http.request.method",
    "proto": "network.protocol",
    "in": "network.bytes_in",
    "out": "network.bytes_out",
    "msg": "message",
    "act": "event.action",
    "outcome": "event.outcome",
    "cs1": "cybernest.cef.cs1",
    "cs2": "cybernest.cef.cs2",
    "cs3": "cybernest.cef.cs3",
    "cs4": "cybernest.cef.cs4",
    "cs5": "cybernest.cef.cs5",
    "cs6": "cybernest.cef.cs6",
    "cn1": "cybernest.cef.cn1",
    "cn2": "cybernest.cef.cn2",
    "cn3": "cybernest.cef.cn3",
    "deviceExternalId": "observer.serial_number",
    "dvchost": "observer.hostname",
    "rt": "@timestamp",
}

# CEF severity mapping (0-10 → ECS severity 0-4)
CEF_SEVERITY_MAP = {
    "0": 0, "1": 0, "2": 0, "3": 1,
    "4": 1, "5": 2, "6": 2, "7": 3,
    "8": 3, "9": 4, "10": 4,
    "Low": 1, "Medium": 2, "High": 3, "Very-High": 4,
}


class CEFParser(BaseParser):
    name = "cef"
    supported_formats = ["cef"]

    def can_parse(self, raw: str) -> bool:
        return "CEF:" in raw

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        m = CEF_HEADER_RE.match(raw)
        if not m:
            return None

        event = ECSEvent().set_raw(raw)

        cef_version = m.group(1)
        vendor = m.group(2)
        product = m.group(3)
        device_version = m.group(4)
        sig_id = m.group(5)
        name = m.group(6)
        severity = m.group(7)
        extensions = m.group(8)

        # Set observer (device) info
        event.set_field("observer.vendor", vendor)
        event.set_field("observer.product", product)
        event.set_field("observer.version", device_version)

        # Set event info
        event.set_event(
            module="cef",
            category=vendor.lower(),
            action=name,
            severity=CEF_SEVERITY_MAP.get(severity, 2),
        )
        event.set_rule(id=sig_id, name=name)
        event.set_field("cybernest.cef.version", cef_version)

        # Parse extensions
        for match in CEF_EXT_RE.finditer(extensions):
            key = match.group(1)
            value = match.group(2).strip()

            ecs_field = CEF_FIELD_MAP.get(key)
            if ecs_field:
                if ecs_field == "@timestamp":
                    event.set_timestamp(value)
                elif ".port" in ecs_field:
                    try:
                        event.set_field(ecs_field, int(value))
                    except ValueError:
                        event.set_field(ecs_field, value)
                else:
                    event.set_field(ecs_field, value)
            else:
                event.set_field(f"cybernest.cef.ext.{key}", value)

        return event

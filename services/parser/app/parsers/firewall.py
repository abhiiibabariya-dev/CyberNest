"""CyberNest Parser — Firewall log parsers (Palo Alto, Fortinet, Cisco ASA)."""

import re
from app.parsers.base import BaseParser, ECSEvent

# Palo Alto traffic log CSV fields
PALO_TRAFFIC_FIELDS = [
    "future_use1", "receive_time", "serial", "type", "threat_content_type",
    "future_use2", "generated_time", "src", "dst", "natsrc", "natdst",
    "rule", "srcuser", "dstuser", "app", "vsys", "from_zone", "to_zone",
    "inbound_if", "outbound_if", "logset", "future_use3", "session_id",
    "repeat_count", "sport", "dport", "natsport", "natdport", "flags",
    "proto", "action",
]

# Cisco ASA patterns
CISCO_ASA_RE = re.compile(
    r"%ASA-(\d)-(\d{6}):\s*(.*)", re.DOTALL
)

# FortiGate key=value
FORTIGATE_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


class PaloAltoParser(BaseParser):
    name = "palo_alto"
    supported_formats = ["palo_alto"]

    def can_parse(self, raw: str) -> bool:
        return raw.count(",") > 20 and ("TRAFFIC" in raw or "THREAT" in raw)

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        fields = raw.split(",")
        if len(fields) < 30:
            return None

        event = ECSEvent().set_raw(raw)
        data = {}
        for i, name in enumerate(PALO_TRAFFIC_FIELDS):
            if i < len(fields):
                data[name] = fields[i]

        event.set_event(
            module="palo_alto",
            category="network",
            action=data.get("action", ""),
        )
        event.set_source(
            ip=data.get("src", ""),
            port=int(data["sport"]) if data.get("sport", "").isdigit() else 0,
        )
        event.set_destination(
            ip=data.get("dst", ""),
            port=int(data["dport"]) if data.get("dport", "").isdigit() else 0,
        )
        event.set_user(name=data.get("srcuser", ""))
        event.set_network(protocol=data.get("proto", ""))
        event.set_rule(name=data.get("rule", ""))
        event.set_field("observer.vendor", "Palo Alto Networks")

        if data.get("generated_time"):
            event.set_timestamp(data["generated_time"])

        return event


class CiscoASAParser(BaseParser):
    name = "cisco_asa"
    supported_formats = ["cisco_asa"]

    def can_parse(self, raw: str) -> bool:
        return "%ASA-" in raw

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        m = CISCO_ASA_RE.search(raw)
        if not m:
            return None

        event = ECSEvent().set_raw(raw)
        severity = int(m.group(1))
        msg_id = m.group(2)
        message = m.group(3)

        event.set_event(
            module="cisco_asa",
            category="network",
            action=msg_id,
            severity=severity,
        )
        event.set_field("message", message)
        event.set_field("observer.vendor", "Cisco")
        event.set_field("observer.product", "ASA")
        event.set_field("cybernest.cisco.message_id", msg_id)

        # Extract IPs from message
        ip_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?")
        ips = ip_re.findall(message)
        if ips:
            event.set_source(ip=ips[0][0], port=int(ips[0][1]) if ips[0][1] else 0)
            if len(ips) > 1:
                event.set_destination(ip=ips[1][0], port=int(ips[1][1]) if ips[1][1] else 0)

        return event


class FortiGateParser(BaseParser):
    name = "fortigate"
    supported_formats = ["fortigate", "fortinet"]

    def can_parse(self, raw: str) -> bool:
        return "devname=" in raw or "logid=" in raw or "type=traffic" in raw.lower()

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        data = {}
        for m in FORTIGATE_RE.finditer(raw):
            key = m.group(1)
            value = m.group(2) if m.group(2) is not None else m.group(3)
            data[key] = value

        if not data:
            return None

        event = ECSEvent().set_raw(raw)

        event.set_event(
            module="fortigate",
            category="network",
            action=data.get("action", ""),
        )
        event.set_source(
            ip=data.get("srcip", ""),
            port=int(data["srcport"]) if data.get("srcport", "").isdigit() else 0,
        )
        event.set_destination(
            ip=data.get("dstip", ""),
            port=int(data["dstport"]) if data.get("dstport", "").isdigit() else 0,
        )
        event.set_user(name=data.get("user", ""))
        event.set_network(
            protocol=data.get("proto", ""),
            bytes_in=int(data["rcvdbyte"]) if data.get("rcvdbyte", "").isdigit() else 0,
            bytes_out=int(data["sentbyte"]) if data.get("sentbyte", "").isdigit() else 0,
        )
        event.set_host(hostname=data.get("devname", ""))
        event.set_rule(name=data.get("policyname", ""))
        event.set_field("observer.vendor", "Fortinet")
        event.set_field("observer.product", "FortiGate")

        if data.get("date") and data.get("time"):
            event.set_timestamp(f"{data['date']}T{data['time']}")

        return event

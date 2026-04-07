"""CyberNest Parser — Syslog parser (RFC 3164 / RFC 5424)."""

import re
from datetime import datetime

from app.parsers.base import BaseParser, ECSEvent

# RFC 3164: <PRI>TIMESTAMP HOSTNAME APP[PID]: MSG
RFC3164_RE = re.compile(
    r"^(?:<(\d{1,3})>)?"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"([\w.\-]+)\s+"
    r"(\S+?)(?:\[(\d+)\])?"
    r":\s*(.*)$",
    re.DOTALL,
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
RFC5424_RE = re.compile(
    r"^<(\d{1,3})>(\d+)\s+"
    r"(\S+)\s+"          # timestamp
    r"(\S+)\s+"          # hostname
    r"(\S+)\s+"          # app-name
    r"(\S+)\s+"          # procid
    r"(\S+)\s+"          # msgid
    r"(?:\[([^\]]*)\]\s*)?"  # structured-data
    r"(.*)$",
    re.DOTALL,
)

# Severity and facility from PRI
SYSLOG_SEVERITY = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}

SYSLOG_FACILITY = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
    18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}

# IP extraction
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class SyslogParser(BaseParser):
    name = "syslog"
    supported_formats = ["syslog", "rfc3164", "rfc5424"]

    def can_parse(self, raw: str) -> bool:
        return bool(RFC3164_RE.match(raw) or RFC5424_RE.match(raw))

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        event = ECSEvent().set_raw(raw)
        metadata = metadata or {}

        # Try RFC 5424 first
        m = RFC5424_RE.match(raw)
        if m:
            return self._parse_5424(m, event, metadata)

        # Try RFC 3164
        m = RFC3164_RE.match(raw)
        if m:
            return self._parse_3164(m, event, metadata)

        return None

    def _parse_3164(self, m: re.Match, event: ECSEvent, metadata: dict) -> ECSEvent:
        pri = int(m.group(1)) if m.group(1) else 13  # default: user.notice
        timestamp = m.group(2)
        hostname = m.group(3)
        program = m.group(4)
        pid = int(m.group(5)) if m.group(5) else 0
        message = m.group(6)

        severity_num = pri % 8
        facility_num = pri // 8

        event.set_event(
            module="syslog",
            category=SYSLOG_FACILITY.get(facility_num, "unknown"),
            action=program,
            severity=severity_num,
        )
        event.set_host(hostname=hostname)
        event.set_process(name=program, pid=pid)
        event.set_field("log.syslog.priority", pri)
        event.set_field("log.syslog.facility.code", facility_num)
        event.set_field("log.syslog.severity.code", severity_num)
        event.set_field("log.syslog.severity.name", SYSLOG_SEVERITY.get(severity_num, "unknown"))
        event.set_field("message", message)

        # Try to parse timestamp
        try:
            year = datetime.now().year
            ts = datetime.strptime(f"{year} {timestamp}", "%Y %b %d %H:%M:%S")
            event.set_timestamp(ts)
        except ValueError:
            pass

        # Extract IPs from message
        ips = IP_RE.findall(message)
        if ips:
            event.set_source(ip=ips[0])
            if len(ips) > 1:
                event.set_destination(ip=ips[1])

        return event

    def _parse_5424(self, m: re.Match, event: ECSEvent, metadata: dict) -> ECSEvent:
        pri = int(m.group(1))
        version = m.group(2)
        timestamp = m.group(3)
        hostname = m.group(4)
        app_name = m.group(5)
        proc_id = m.group(6)
        msg_id = m.group(7)
        structured_data = m.group(8)
        message = m.group(9)

        severity_num = pri % 8
        facility_num = pri // 8

        event.set_event(
            module="syslog",
            category=SYSLOG_FACILITY.get(facility_num, "unknown"),
            action=app_name,
            severity=severity_num,
        )
        event.set_host(hostname=hostname if hostname != "-" else "")
        event.set_process(
            name=app_name if app_name != "-" else "",
            pid=int(proc_id) if proc_id not in ("-", "") else 0,
        )
        event.set_field("log.syslog.priority", pri)
        event.set_field("log.syslog.version", int(version))
        event.set_field("log.syslog.msgid", msg_id if msg_id != "-" else "")
        event.set_field("message", message)

        if timestamp != "-":
            event.set_timestamp(timestamp)

        ips = IP_RE.findall(message)
        if ips:
            event.set_source(ip=ips[0])
            if len(ips) > 1:
                event.set_destination(ip=ips[1])

        return event

"""CyberNest Parser — Linux log parsers (auth.log, auditd, Apache/Nginx)."""

import re
from datetime import datetime
from app.parsers.base import BaseParser, ECSEvent

# auth.log patterns
AUTH_FAILED_RE = re.compile(
    r"Failed (\w+) for (?:invalid user )?(\S+) from (\S+) port (\d+)"
)
AUTH_ACCEPTED_RE = re.compile(
    r"Accepted (\w+) for (\S+) from (\S+) port (\d+)"
)
SUDO_RE = re.compile(
    r"(\S+)\s*:\s*(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)"
)
USERADD_RE = re.compile(r"new user: name=(\S+)")
USERDEL_RE = re.compile(r"delete user '(\S+)'")

# Auditd
AUDIT_RE = re.compile(r"type=(\S+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)")

# Apache/Nginx Combined Log Format
ACCESS_LOG_RE = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LinuxAuthParser(BaseParser):
    name = "linux_auth"
    supported_formats = ["auth", "authlog"]

    def can_parse(self, raw: str) -> bool:
        return any(kw in raw for kw in ["sshd", "sudo", "pam_unix", "useradd", "userdel", "su:"])

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        event = ECSEvent().set_raw(raw)
        event.set_event(module="linux_auth")

        # Failed login
        m = AUTH_FAILED_RE.search(raw)
        if m:
            event.set_event(category="authentication", action="logon_failure", outcome="failure")
            event.set_user(name=m.group(2))
            event.set_source(ip=m.group(3), port=int(m.group(4)))
            event.set_process(name="sshd")
            return event

        # Accepted login
        m = AUTH_ACCEPTED_RE.search(raw)
        if m:
            event.set_event(category="authentication", action="logon_success", outcome="success")
            event.set_user(name=m.group(2))
            event.set_source(ip=m.group(3), port=int(m.group(4)))
            event.set_process(name="sshd")
            return event

        # Sudo
        m = SUDO_RE.search(raw)
        if m:
            event.set_event(category="iam", action="sudo_executed")
            event.set_user(name=m.group(2))
            event.set_field("user.target.name", m.group(3))
            event.set_process(command_line=m.group(4).strip())
            return event

        # User management
        m = USERADD_RE.search(raw)
        if m:
            event.set_event(category="iam", action="user_created")
            event.set_user(name=m.group(1))
            return event

        m = USERDEL_RE.search(raw)
        if m:
            event.set_event(category="iam", action="user_deleted")
            event.set_user(name=m.group(1))
            return event

        # Generic auth log
        event.set_event(category="authentication", action="auth_event")
        ips = IP_RE.findall(raw)
        if ips:
            event.set_source(ip=ips[0])
        return event


class AuditdParser(BaseParser):
    name = "auditd"
    supported_formats = ["auditd", "audit"]

    def can_parse(self, raw: str) -> bool:
        return "type=" in raw and "msg=audit(" in raw

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        m = AUDIT_RE.match(raw)
        if not m:
            return None

        event = ECSEvent().set_raw(raw)
        audit_type = m.group(1)
        timestamp = float(m.group(2))
        serial = m.group(3)
        fields_str = m.group(4)

        event.set_timestamp(datetime.fromtimestamp(timestamp))
        event.set_event(module="auditd", category="process", action=audit_type)
        event.set_field("cybernest.auditd.type", audit_type)
        event.set_field("cybernest.auditd.serial", serial)

        # Parse key=value or key="value"
        field_re = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
        data = {}
        for fm in field_re.finditer(fields_str):
            data[fm.group(1)] = fm.group(2) if fm.group(2) is not None else fm.group(3)

        if "uid" in data:
            event.set_user(id=data["uid"], name=data.get("auid", ""))
        if "exe" in data:
            event.set_process(name=data["exe"].strip('"').split("/")[-1])
        if "comm" in data:
            event.set_process(command_line=data["comm"].strip('"'))

        event.set_host(os_type="linux")
        return event


class WebAccessLogParser(BaseParser):
    name = "web_access"
    supported_formats = ["apache", "nginx", "access_log"]

    def can_parse(self, raw: str) -> bool:
        return bool(ACCESS_LOG_RE.match(raw))

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        m = ACCESS_LOG_RE.match(raw)
        if not m:
            return None

        event = ECSEvent().set_raw(raw)
        client_ip = m.group(1)
        user = m.group(2)
        timestamp = m.group(3)
        method = m.group(4)
        path = m.group(5)
        protocol = m.group(6)
        status = int(m.group(7))
        bytes_sent = int(m.group(8))
        referrer = m.group(9)
        user_agent = m.group(10)

        event.set_event(
            module="web",
            category="web",
            action="access",
            outcome="success" if status < 400 else "failure",
        )
        event.set_source(ip=client_ip)
        event.set_user(name=user if user != "-" else "")
        event.set_field("url.path", path)
        event.set_field("http.request.method", method)
        event.set_field("http.response.status_code", status)
        event.set_field("http.response.bytes", bytes_sent)
        event.set_field("http.request.referrer", referrer if referrer != "-" else "")
        event.set_field("user_agent.original", user_agent)
        event.set_network(protocol=protocol.lower().split("/")[0] if "/" in protocol else "http")

        return event

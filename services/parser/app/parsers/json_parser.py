"""CyberNest Parser — JSON log parser (passthrough with enrichment).
Handles: generic JSON logs, Suricata EVE, AWS CloudTrail, Azure Activity, GCP Audit.
"""

import json
from app.parsers.base import BaseParser, ECSEvent


class JSONParser(BaseParser):
    name = "json"
    supported_formats = ["json"]

    def can_parse(self, raw: str) -> bool:
        stripped = raw.strip()
        return stripped.startswith("{") and stripped.endswith("}")

    def parse(self, raw: str, metadata: dict | None = None) -> ECSEvent | None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None

        event = ECSEvent().set_raw(raw)

        # Detect and route to specialized parsers
        if "event_type" in data and "src_ip" in data:
            return self._parse_suricata(data, event)
        if "eventSource" in data and "awsRegion" in data:
            return self._parse_cloudtrail(data, event)
        if "category" in data and "operationName" in data and "resourceId" in data:
            return self._parse_azure_activity(data, event)
        if "protoPayload" in data and "resource" in data:
            return self._parse_gcp_audit(data, event)

        # Generic JSON — flatten into ECS
        return self._parse_generic(data, event)

    def _parse_suricata(self, data: dict, event: ECSEvent) -> ECSEvent:
        event.set_event(module="suricata", category="network", action=data.get("event_type", ""))
        event.set_source(ip=data.get("src_ip", ""), port=data.get("src_port", 0))
        event.set_destination(ip=data.get("dest_ip", ""), port=data.get("dest_port", 0))
        event.set_network(protocol=data.get("proto", ""))

        if data.get("timestamp"):
            event.set_timestamp(data["timestamp"])

        # Alert details
        alert = data.get("alert", {})
        if alert:
            event.set_rule(
                id=str(alert.get("signature_id", "")),
                name=alert.get("signature", ""),
                level=alert.get("severity", 0),
            )
            event.set_event(action=alert.get("action", ""))

        # DNS
        dns = data.get("dns", {})
        if dns:
            event.set_field("dns.question.name", dns.get("rrname", ""))
            event.set_field("dns.question.type", dns.get("rrtype", ""))

        # HTTP
        http = data.get("http", {})
        if http:
            event.set_field("url.original", http.get("url", ""))
            event.set_field("http.request.method", http.get("http_method", ""))
            event.set_field("http.response.status_code", http.get("status", 0))

        event.set_field("cybernest.suricata.flow_id", data.get("flow_id"))
        return event

    def _parse_cloudtrail(self, data: dict, event: ECSEvent) -> ECSEvent:
        event.set_event(
            module="aws_cloudtrail",
            category="cloud",
            action=data.get("eventName", ""),
            outcome="success" if not data.get("errorCode") else "failure",
        )
        event.set_user(name=data.get("userIdentity", {}).get("userName", ""))
        event.set_source(ip=data.get("sourceIPAddress", ""))

        if data.get("eventTime"):
            event.set_timestamp(data["eventTime"])

        event.set_field("cloud.provider", "aws")
        event.set_field("cloud.region", data.get("awsRegion", ""))
        event.set_field("cloud.account.id", data.get("recipientAccountId", ""))
        event.set_field("event.provider", data.get("eventSource", ""))

        if data.get("errorCode"):
            event.set_field("error.code", data["errorCode"])
            event.set_field("error.message", data.get("errorMessage", ""))

        return event

    def _parse_azure_activity(self, data: dict, event: ECSEvent) -> ECSEvent:
        event.set_event(
            module="azure_activity",
            category="cloud",
            action=data.get("operationName", ""),
        )
        if data.get("time"):
            event.set_timestamp(data["time"])

        caller = data.get("caller", "")
        if "@" in caller:
            event.set_user(name=caller)
        event.set_source(ip=data.get("callerIpAddress", ""))

        event.set_field("cloud.provider", "azure")
        event.set_field("cloud.resource.id", data.get("resourceId", ""))
        return event

    def _parse_gcp_audit(self, data: dict, event: ECSEvent) -> ECSEvent:
        proto = data.get("protoPayload", {})
        event.set_event(
            module="gcp_audit",
            category="cloud",
            action=proto.get("methodName", ""),
        )
        if data.get("timestamp"):
            event.set_timestamp(data["timestamp"])

        auth_info = proto.get("authenticationInfo", {})
        event.set_user(name=auth_info.get("principalEmail", ""))
        event.set_source(ip=proto.get("requestMetadata", {}).get("callerIp", ""))

        event.set_field("cloud.provider", "gcp")
        event.set_field("cloud.project.id", data.get("resource", {}).get("labels", {}).get("project_id", ""))
        return event

    def _parse_generic(self, data: dict, event: ECSEvent) -> ECSEvent:
        event.set_event(module="json", category="generic")

        # Try to extract common fields
        for ts_field in ("timestamp", "@timestamp", "time", "datetime", "date", "ts"):
            if ts_field in data:
                event.set_timestamp(str(data[ts_field]))
                break

        for ip_field in ("src_ip", "source_ip", "srcip", "client_ip", "ip"):
            if ip_field in data:
                event.set_source(ip=str(data[ip_field]))
                break

        for dst_field in ("dst_ip", "dest_ip", "dstip", "destination_ip"):
            if dst_field in data:
                event.set_destination(ip=str(data[dst_field]))
                break

        for user_field in ("user", "username", "user_name", "userName"):
            if user_field in data:
                event.set_user(name=str(data[user_field]))
                break

        for msg_field in ("message", "msg", "description", "detail"):
            if msg_field in data:
                event.set_field("message", str(data[msg_field]))
                break

        for action_field in ("action", "event", "event_type", "type"):
            if action_field in data:
                event.set_event(action=str(data[action_field]))
                break

        # Store remaining fields
        event.set_field("cybernest.json.original", data)
        return event

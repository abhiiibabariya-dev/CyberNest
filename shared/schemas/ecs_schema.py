"""CyberNest — ECS field definitions and Elasticsearch mapping constants.

Defines the canonical field list for index templates and parser validation.
Based on Elastic Common Schema 8.x.
"""

# ECS field → Elasticsearch mapping type
ECS_FIELD_MAPPINGS: dict[str, dict] = {
    "@timestamp": {"type": "date"},
    "message": {"type": "text"},
    "raw": {"type": "text", "index": False},
    "tags": {"type": "keyword"},
    "labels": {"type": "object", "dynamic": True},
    # Event
    "event.module": {"type": "keyword"},
    "event.category": {"type": "keyword"},
    "event.action": {"type": "keyword"},
    "event.outcome": {"type": "keyword"},
    "event.kind": {"type": "keyword"},
    "event.severity": {"type": "integer"},
    "event.type": {"type": "keyword"},
    "event.dataset": {"type": "keyword"},
    "event.provider": {"type": "keyword"},
    "event.risk_score": {"type": "float"},
    # Source
    "source.ip": {"type": "ip"},
    "source.port": {"type": "integer"},
    "source.domain": {"type": "keyword"},
    "source.mac": {"type": "keyword"},
    "source.geo.country_iso_code": {"type": "keyword"},
    "source.geo.country_name": {"type": "keyword"},
    "source.geo.city_name": {"type": "keyword"},
    "source.geo.location": {"type": "geo_point"},
    "source.as.number": {"type": "long"},
    "source.as.organization.name": {"type": "keyword"},
    # Destination
    "destination.ip": {"type": "ip"},
    "destination.port": {"type": "integer"},
    "destination.domain": {"type": "keyword"},
    "destination.geo.country_iso_code": {"type": "keyword"},
    "destination.geo.country_name": {"type": "keyword"},
    # User
    "user.name": {"type": "keyword"},
    "user.domain": {"type": "keyword"},
    "user.id": {"type": "keyword"},
    "user.email": {"type": "keyword"},
    # Process
    "process.name": {"type": "keyword"},
    "process.pid": {"type": "integer"},
    "process.command_line": {"type": "text"},
    "process.executable": {"type": "keyword"},
    "process.parent.name": {"type": "keyword"},
    "process.parent.pid": {"type": "integer"},
    "process.hash.sha256": {"type": "keyword"},
    "process.hash.md5": {"type": "keyword"},
    # Host
    "host.hostname": {"type": "keyword"},
    "host.ip": {"type": "ip"},
    "host.os.type": {"type": "keyword"},
    "host.os.name": {"type": "keyword"},
    "host.os.version": {"type": "keyword"},
    # Network
    "network.protocol": {"type": "keyword"},
    "network.transport": {"type": "keyword"},
    "network.direction": {"type": "keyword"},
    "network.bytes": {"type": "long"},
    "network.community_id": {"type": "keyword"},
    # File
    "file.path": {"type": "keyword"},
    "file.name": {"type": "keyword"},
    "file.extension": {"type": "keyword"},
    "file.size": {"type": "long"},
    "file.hash.sha256": {"type": "keyword"},
    "file.hash.md5": {"type": "keyword"},
    # DNS
    "dns.question.name": {"type": "keyword"},
    "dns.question.type": {"type": "keyword"},
    "dns.response_code": {"type": "keyword"},
    # URL / HTTP
    "url.original": {"type": "keyword"},
    "url.path": {"type": "keyword"},
    "url.domain": {"type": "keyword"},
    "http.request.method": {"type": "keyword"},
    "http.response.status_code": {"type": "integer"},
    "http.response.bytes": {"type": "long"},
    # Cloud
    "cloud.provider": {"type": "keyword"},
    "cloud.region": {"type": "keyword"},
    "cloud.account.id": {"type": "keyword"},
    "cloud.project.id": {"type": "keyword"},
    # Observer (firewall, IDS)
    "observer.vendor": {"type": "keyword"},
    "observer.product": {"type": "keyword"},
    "observer.version": {"type": "keyword"},
    # Rule (from correlator)
    "rule.id": {"type": "keyword"},
    "rule.name": {"type": "keyword"},
    "rule.level": {"type": "integer"},
    "rule.category": {"type": "keyword"},
    "rule.mitre.technique": {"type": "keyword"},
    "rule.mitre.tactic": {"type": "keyword"},
    # Threat Intel
    "threat_intel.matched": {"type": "boolean"},
    "threat_intel.ioc_type": {"type": "keyword"},
    "threat_intel.ioc_value": {"type": "keyword"},
    "threat_intel.threat_score": {"type": "float"},
    "threat_intel.source": {"type": "keyword"},
    # Agent
    "agent.id": {"type": "keyword"},
    "agent.hostname": {"type": "keyword"},
    "agent.version": {"type": "keyword"},
    "agent.os": {"type": "keyword"},
    # Windows-specific
    "winlog.event_id": {"type": "integer"},
    "winlog.channel": {"type": "keyword"},
    "winlog.provider_name": {"type": "keyword"},
    "winlog.logon.type": {"type": "keyword"},
    "winlog.event_data": {"type": "object", "dynamic": True},
    # CyberNest metadata
    "cybernest.event_id": {"type": "keyword"},
    "cybernest.parser_name": {"type": "keyword"},
    "cybernest.parse_status": {"type": "keyword"},
    "cybernest.parse_duration_ms": {"type": "float"},
    "cybernest.agent_id": {"type": "keyword"},
    "cybernest.source_name": {"type": "keyword"},
}


def build_es_mappings() -> dict:
    """Build nested Elasticsearch mappings dict from flat ECS field list."""
    properties: dict = {}
    for field_path, mapping in ECS_FIELD_MAPPINGS.items():
        parts = field_path.split(".")
        current = properties
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                current[part] = mapping
            else:
                if part not in current:
                    current[part] = {"properties": {}}
                elif "properties" not in current[part]:
                    current[part]["properties"] = {}
                current = current[part]["properties"]
    return {"properties": properties}

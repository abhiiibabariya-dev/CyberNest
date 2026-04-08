"""
CyberNest ECS Field Mapping for Elasticsearch.

Defines the canonical ECS 8.x field-to-Elasticsearch-type mapping used to
generate index templates. Covers all standard ECS field sets plus CyberNest
custom fields.

Usage:
    from shared.schemas.ecs_schema import ECS_FIELD_MAPPINGS, build_es_mappings
    mappings = build_es_mappings()  # nested dict ready for PUT _index_template
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# ECS field -> Elasticsearch mapping type
# ---------------------------------------------------------------------------

ECS_FIELD_MAPPINGS: dict[str, dict[str, Any]] = {
    # === Base fields =======================================================
    "@timestamp": {"type": "date"},
    "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
    "tags": {"type": "keyword"},
    "labels": {"type": "object", "dynamic": True},
    "ecs.version": {"type": "keyword"},
    "raw": {"type": "text", "index": False},

    # === Event =============================================================
    "event.kind": {"type": "keyword"},
    "event.category": {"type": "keyword"},
    "event.type": {"type": "keyword"},
    "event.action": {"type": "keyword"},
    "event.outcome": {"type": "keyword"},
    "event.module": {"type": "keyword"},
    "event.dataset": {"type": "keyword"},
    "event.severity": {"type": "integer"},
    "event.risk_score": {"type": "float"},
    "event.risk_score_norm": {"type": "float"},
    "event.id": {"type": "keyword"},
    "event.code": {"type": "keyword"},
    "event.provider": {"type": "keyword"},
    "event.original": {"type": "text", "index": False},
    "event.hash": {"type": "keyword"},
    "event.duration": {"type": "long"},
    "event.sequence": {"type": "long"},
    "event.created": {"type": "date"},
    "event.start": {"type": "date"},
    "event.end": {"type": "date"},
    "event.timezone": {"type": "keyword"},
    "event.ingested": {"type": "date"},
    "event.url": {"type": "keyword"},
    "event.reason": {"type": "keyword"},
    "event.reference": {"type": "keyword"},

    # === Source ============================================================
    "source.ip": {"type": "ip"},
    "source.port": {"type": "integer"},
    "source.mac": {"type": "keyword"},
    "source.domain": {"type": "keyword"},
    "source.bytes": {"type": "long"},
    "source.packets": {"type": "long"},
    "source.registered_domain": {"type": "keyword"},
    "source.top_level_domain": {"type": "keyword"},
    "source.nat.ip": {"type": "ip"},
    "source.nat.port": {"type": "integer"},
    "source.geo.city_name": {"type": "keyword"},
    "source.geo.continent_code": {"type": "keyword"},
    "source.geo.continent_name": {"type": "keyword"},
    "source.geo.country_iso_code": {"type": "keyword"},
    "source.geo.country_name": {"type": "keyword"},
    "source.geo.location": {"type": "geo_point"},
    "source.geo.name": {"type": "keyword"},
    "source.geo.postal_code": {"type": "keyword"},
    "source.geo.region_iso_code": {"type": "keyword"},
    "source.geo.region_name": {"type": "keyword"},
    "source.geo.timezone": {"type": "keyword"},
    "source.as.number": {"type": "long"},
    "source.as.organization_name": {"type": "keyword"},

    # === Destination =======================================================
    "destination.ip": {"type": "ip"},
    "destination.port": {"type": "integer"},
    "destination.mac": {"type": "keyword"},
    "destination.domain": {"type": "keyword"},
    "destination.bytes": {"type": "long"},
    "destination.packets": {"type": "long"},
    "destination.registered_domain": {"type": "keyword"},
    "destination.top_level_domain": {"type": "keyword"},
    "destination.nat.ip": {"type": "ip"},
    "destination.nat.port": {"type": "integer"},
    "destination.geo.city_name": {"type": "keyword"},
    "destination.geo.continent_code": {"type": "keyword"},
    "destination.geo.continent_name": {"type": "keyword"},
    "destination.geo.country_iso_code": {"type": "keyword"},
    "destination.geo.country_name": {"type": "keyword"},
    "destination.geo.location": {"type": "geo_point"},
    "destination.geo.name": {"type": "keyword"},
    "destination.geo.postal_code": {"type": "keyword"},
    "destination.geo.region_iso_code": {"type": "keyword"},
    "destination.geo.region_name": {"type": "keyword"},
    "destination.geo.timezone": {"type": "keyword"},
    "destination.as.number": {"type": "long"},
    "destination.as.organization_name": {"type": "keyword"},

    # === Host ==============================================================
    "host.name": {"type": "keyword"},
    "host.hostname": {"type": "keyword"},
    "host.id": {"type": "keyword"},
    "host.ip": {"type": "ip"},
    "host.mac": {"type": "keyword"},
    "host.domain": {"type": "keyword"},
    "host.type": {"type": "keyword"},
    "host.uptime": {"type": "long"},
    "host.architecture": {"type": "keyword"},
    "host.os.family": {"type": "keyword"},
    "host.os.full": {"type": "keyword"},
    "host.os.kernel": {"type": "keyword"},
    "host.os.name": {"type": "keyword"},
    "host.os.platform": {"type": "keyword"},
    "host.os.type": {"type": "keyword"},
    "host.os.version": {"type": "keyword"},

    # === User ==============================================================
    "user.name": {"type": "keyword"},
    "user.full_name": {"type": "keyword"},
    "user.domain": {"type": "keyword"},
    "user.id": {"type": "keyword"},
    "user.email": {"type": "keyword"},
    "user.hash": {"type": "keyword"},
    "user.roles": {"type": "keyword"},

    # === Process ===========================================================
    "process.pid": {"type": "long"},
    "process.name": {"type": "keyword"},
    "process.executable": {"type": "keyword"},
    "process.command_line": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}}},
    "process.args": {"type": "keyword"},
    "process.working_directory": {"type": "keyword"},
    "process.start": {"type": "date"},
    "process.end": {"type": "date"},
    "process.exit_code": {"type": "integer"},
    "process.title": {"type": "keyword"},
    "process.thread.id": {"type": "long"},
    "process.entity_id": {"type": "keyword"},
    "process.hash.md5": {"type": "keyword"},
    "process.hash.sha1": {"type": "keyword"},
    "process.hash.sha256": {"type": "keyword"},
    "process.hash.sha512": {"type": "keyword"},
    "process.parent.pid": {"type": "long"},
    "process.parent.name": {"type": "keyword"},
    "process.parent.executable": {"type": "keyword"},
    "process.parent.command_line": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}}},
    "process.parent.args": {"type": "keyword"},
    "process.parent.entity_id": {"type": "keyword"},

    # === File ==============================================================
    "file.name": {"type": "keyword"},
    "file.path": {"type": "keyword"},
    "file.directory": {"type": "keyword"},
    "file.extension": {"type": "keyword"},
    "file.mime_type": {"type": "keyword"},
    "file.size": {"type": "long"},
    "file.type": {"type": "keyword"},
    "file.uid": {"type": "keyword"},
    "file.gid": {"type": "keyword"},
    "file.owner": {"type": "keyword"},
    "file.group": {"type": "keyword"},
    "file.mode": {"type": "keyword"},
    "file.inode": {"type": "keyword"},
    "file.device": {"type": "keyword"},
    "file.target_path": {"type": "keyword"},
    "file.hash.md5": {"type": "keyword"},
    "file.hash.sha1": {"type": "keyword"},
    "file.hash.sha256": {"type": "keyword"},
    "file.hash.sha512": {"type": "keyword"},
    "file.hash.ssdeep": {"type": "keyword"},
    "file.hash.tlsh": {"type": "keyword"},
    "file.created": {"type": "date"},
    "file.accessed": {"type": "date"},
    "file.mtime": {"type": "date"},
    "file.ctime": {"type": "date"},

    # === Network ===========================================================
    "network.protocol": {"type": "keyword"},
    "network.transport": {"type": "keyword"},
    "network.type": {"type": "keyword"},
    "network.application": {"type": "keyword"},
    "network.direction": {"type": "keyword"},
    "network.bytes": {"type": "long"},
    "network.packets": {"type": "long"},
    "network.community_id": {"type": "keyword"},
    "network.forwarded_ip": {"type": "ip"},
    "network.iana_number": {"type": "keyword"},
    "network.name": {"type": "keyword"},
    "network.vlan.id": {"type": "keyword"},
    "network.vlan.name": {"type": "keyword"},

    # === DNS ===============================================================
    "dns.id": {"type": "keyword"},
    "dns.op_code": {"type": "keyword"},
    "dns.type": {"type": "keyword"},
    "dns.response_code": {"type": "keyword"},
    "dns.header_flags": {"type": "keyword"},
    "dns.question.name": {"type": "keyword"},
    "dns.question.type": {"type": "keyword"},
    "dns.question.class": {"type": "keyword"},
    "dns.question.registered_domain": {"type": "keyword"},
    "dns.question.subdomain": {"type": "keyword"},
    "dns.question.top_level_domain": {"type": "keyword"},
    "dns.answers.name": {"type": "keyword"},
    "dns.answers.type": {"type": "keyword"},
    "dns.answers.class": {"type": "keyword"},
    "dns.answers.data": {"type": "keyword"},
    "dns.answers.ttl": {"type": "long"},
    "dns.resolved_ip": {"type": "ip"},

    # === HTTP ==============================================================
    "http.version": {"type": "keyword"},
    "http.request.method": {"type": "keyword"},
    "http.request.bytes": {"type": "long"},
    "http.request.referrer": {"type": "keyword"},
    "http.request.mime_type": {"type": "keyword"},
    "http.request.body.bytes": {"type": "long"},
    "http.request.body.content": {"type": "text", "index": False},
    "http.response.status_code": {"type": "integer"},
    "http.response.bytes": {"type": "long"},
    "http.response.mime_type": {"type": "keyword"},
    "http.response.body.bytes": {"type": "long"},
    "http.response.body.content": {"type": "text", "index": False},

    # === URL ===============================================================
    "url.full": {"type": "keyword"},
    "url.original": {"type": "keyword"},
    "url.scheme": {"type": "keyword"},
    "url.domain": {"type": "keyword"},
    "url.port": {"type": "integer"},
    "url.path": {"type": "keyword"},
    "url.query": {"type": "keyword"},
    "url.fragment": {"type": "keyword"},
    "url.username": {"type": "keyword"},
    "url.password": {"type": "keyword"},
    "url.registered_domain": {"type": "keyword"},
    "url.top_level_domain": {"type": "keyword"},
    "url.extension": {"type": "keyword"},

    # === Rule ==============================================================
    "rule.id": {"type": "keyword"},
    "rule.name": {"type": "keyword"},
    "rule.description": {"type": "text"},
    "rule.category": {"type": "keyword"},
    "rule.ruleset": {"type": "keyword"},
    "rule.version": {"type": "keyword"},
    "rule.author": {"type": "keyword"},
    "rule.license": {"type": "keyword"},
    "rule.reference": {"type": "keyword"},
    "rule.uuid": {"type": "keyword"},

    # === Threat ============================================================
    "threat.framework": {"type": "keyword"},
    "threat.tactic.id": {"type": "keyword"},
    "threat.tactic.name": {"type": "keyword"},
    "threat.tactic.reference": {"type": "keyword"},
    "threat.technique.id": {"type": "keyword"},
    "threat.technique.name": {"type": "keyword"},
    "threat.technique.reference": {"type": "keyword"},
    "threat.indicator.type": {"type": "keyword"},
    "threat.indicator.description": {"type": "text"},
    "threat.indicator.provider": {"type": "keyword"},
    "threat.indicator.reference": {"type": "keyword"},
    "threat.indicator.confidence": {"type": "keyword"},
    "threat.indicator.scanner_stats": {"type": "integer"},
    "threat.indicator.sightings": {"type": "integer"},
    "threat.indicator.first_seen": {"type": "date"},
    "threat.indicator.last_seen": {"type": "date"},
    "threat.indicator.marking.tlp": {"type": "keyword"},
    "threat.indicator.ip": {"type": "ip"},
    "threat.indicator.domain": {"type": "keyword"},
    "threat.indicator.port": {"type": "integer"},
    "threat.indicator.email.address": {"type": "keyword"},
    "threat.indicator.url.full": {"type": "keyword"},
    "threat.indicator.file.hash.sha256": {"type": "keyword"},
    "threat.indicator.file.hash.md5": {"type": "keyword"},

    # === Agent =============================================================
    "agent.id": {"type": "keyword"},
    "agent.name": {"type": "keyword"},
    "agent.type": {"type": "keyword"},
    "agent.version": {"type": "keyword"},
    "agent.ephemeral_id": {"type": "keyword"},

    # === Log ===============================================================
    "log.level": {"type": "keyword"},
    "log.logger": {"type": "keyword"},
    "log.file.path": {"type": "keyword"},

    # === Observer (firewall, IDS, etc.) ====================================
    "observer.hostname": {"type": "keyword"},
    "observer.ip": {"type": "ip"},
    "observer.mac": {"type": "keyword"},
    "observer.name": {"type": "keyword"},
    "observer.product": {"type": "keyword"},
    "observer.serial_number": {"type": "keyword"},
    "observer.type": {"type": "keyword"},
    "observer.vendor": {"type": "keyword"},
    "observer.version": {"type": "keyword"},

    # === Cloud =============================================================
    "cloud.provider": {"type": "keyword"},
    "cloud.account.id": {"type": "keyword"},
    "cloud.account.name": {"type": "keyword"},
    "cloud.region": {"type": "keyword"},
    "cloud.availability_zone": {"type": "keyword"},
    "cloud.instance.id": {"type": "keyword"},
    "cloud.instance.name": {"type": "keyword"},
    "cloud.machine.type": {"type": "keyword"},
    "cloud.project.id": {"type": "keyword"},

    # === Container =========================================================
    "container.id": {"type": "keyword"},
    "container.name": {"type": "keyword"},
    "container.image.name": {"type": "keyword"},
    "container.image.tag": {"type": "keyword"},
    "container.runtime": {"type": "keyword"},
    "container.labels": {"type": "object", "dynamic": True},

    # === Error =============================================================
    "error.code": {"type": "keyword"},
    "error.id": {"type": "keyword"},
    "error.message": {"type": "text"},
    "error.stack_trace": {"type": "text", "index": False},
    "error.type": {"type": "keyword"},

    # === Service ===========================================================
    "service.id": {"type": "keyword"},
    "service.name": {"type": "keyword"},
    "service.type": {"type": "keyword"},
    "service.version": {"type": "keyword"},
    "service.environment": {"type": "keyword"},
    "service.ephemeral_id": {"type": "keyword"},
    "service.node.name": {"type": "keyword"},
    "service.state": {"type": "keyword"},

    # === Related (pivot fields) ============================================
    "related.ip": {"type": "ip"},
    "related.user": {"type": "keyword"},
    "related.hash": {"type": "keyword"},
    "related.hosts": {"type": "keyword"},

    # === CyberNest custom ==================================================
    "cybernest.event_id": {"type": "keyword"},
    "cybernest.parser_name": {"type": "keyword"},
    "cybernest.parse_status": {"type": "keyword"},
    "cybernest.parse_time": {"type": "keyword"},
    "cybernest.parse_duration_ms": {"type": "float"},
    "cybernest.parser_version": {"type": "keyword"},
    "cybernest.source_name": {"type": "keyword"},
    "cybernest.agent_id": {"type": "keyword"},
    "cybernest.ingested_at": {"type": "date"},
}


def build_es_mappings() -> dict[str, Any]:
    """Build a nested Elasticsearch mappings dict from the flat ECS field list.

    Returns a dict suitable for use as the ``mappings`` body in an
    Elasticsearch index template ``PUT _index_template`` request.

    Example output structure::

        {
            "properties": {
                "@timestamp": {"type": "date"},
                "event": {
                    "properties": {
                        "kind": {"type": "keyword"},
                        ...
                    }
                },
                ...
            }
        }
    """
    properties: dict[str, Any] = {}

    for field_path, mapping in ECS_FIELD_MAPPINGS.items():
        parts = field_path.split(".")
        current = properties

        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                # Leaf node — apply the mapping
                current[part] = mapping
            else:
                # Intermediate node — ensure nested properties dict
                if part not in current:
                    current[part] = {"properties": {}}
                elif "properties" not in current[part]:
                    current[part]["properties"] = {}
                current = current[part]["properties"]

    return {"properties": properties}


def build_index_template(
    index_pattern: str = "cybernest-events-*",
    template_name: str = "cybernest-events",
    number_of_shards: int = 1,
    number_of_replicas: int = 1,
    refresh_interval: str = "5s",
) -> dict[str, Any]:
    """Build a complete Elasticsearch index template body.

    Args:
        index_pattern: Glob pattern for indices this template applies to.
        template_name: Template name.
        number_of_shards: Primary shard count.
        number_of_replicas: Replica count.
        refresh_interval: Index refresh interval.

    Returns:
        Dict ready to be sent as the body of
        ``PUT _index_template/{template_name}``.
    """
    return {
        "index_patterns": [index_pattern],
        "template": {
            "settings": {
                "number_of_shards": number_of_shards,
                "number_of_replicas": number_of_replicas,
                "refresh_interval": refresh_interval,
                "index.mapping.total_fields.limit": 2000,
            },
            "mappings": {
                **build_es_mappings(),
                "dynamic": "false",
                "_source": {"enabled": True},
            },
        },
        "priority": 200,
        "composed_of": [],
        "_meta": {
            "description": f"CyberNest SIEM ECS event index template ({template_name})",
            "ecs_version": "8.11.0",
        },
    }

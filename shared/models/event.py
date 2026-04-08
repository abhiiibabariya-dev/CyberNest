"""
CyberNest ECS (Elastic Common Schema) Event Model.

Full Pydantic v2 implementation of ECS 8.x fields for normalized security event
representation across the entire SIEM pipeline.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventKind(str, Enum):
    ALERT = "alert"
    ENRICHMENT = "enrichment"
    EVENT = "event"
    METRIC = "metric"
    STATE = "state"
    PIPELINE_ERROR = "pipeline_error"
    SIGNAL = "signal"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    DRIVER = "driver"
    EMAIL = "email"
    FILE = "file"
    HOST = "host"
    IAM = "iam"
    INTRUSION_DETECTION = "intrusion_detection"
    MALWARE = "malware"
    NETWORK = "network"
    PACKAGE = "package"
    PROCESS = "process"
    REGISTRY = "registry"
    SESSION = "session"
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    WEB = "web"


class EventType(str, Enum):
    ACCESS = "access"
    ADMIN = "admin"
    ALLOWED = "allowed"
    CHANGE = "change"
    CONNECTION = "connection"
    CREATION = "creation"
    DELETION = "deletion"
    DENIED = "denied"
    END = "end"
    ERROR = "error"
    GROUP = "group"
    INDICATOR = "indicator"
    INFO = "info"
    INSTALLATION = "installation"
    PROTOCOL = "protocol"
    START = "start"
    USER = "user"


class EventOutcome(str, Enum):
    FAILURE = "failure"
    SUCCESS = "success"
    UNKNOWN = "unknown"


class NetworkDirection(str, Enum):
    INGRESS = "ingress"
    EGRESS = "egress"
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Nested ECS sub-models
# ---------------------------------------------------------------------------

class ECSGeo(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    city_name: Optional[str] = Field(None, alias="city_name")
    continent_code: Optional[str] = Field(None, alias="continent_code")
    continent_name: Optional[str] = Field(None, alias="continent_name")
    country_iso_code: Optional[str] = Field(None, alias="country_iso_code")
    country_name: Optional[str] = Field(None, alias="country_name")
    location: Optional[dict[str, float]] = Field(
        None, description="GeoJSON point: {lat, lon}"
    )
    name: Optional[str] = None
    postal_code: Optional[str] = Field(None, alias="postal_code")
    region_iso_code: Optional[str] = Field(None, alias="region_iso_code")
    region_name: Optional[str] = Field(None, alias="region_name")
    timezone: Optional[str] = None


class ECSAS(BaseModel):
    """Autonomous System information."""

    model_config = {"populate_by_name": True, "extra": "allow"}

    number: Optional[int] = None
    organization_name: Optional[str] = Field(None, alias="organization_name")


class ECSSource(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=0, le=65535)
    mac: Optional[str] = None
    domain: Optional[str] = None
    bytes: Optional[int] = Field(None, ge=0)
    packets: Optional[int] = Field(None, ge=0)
    registered_domain: Optional[str] = Field(None, alias="registered_domain")
    top_level_domain: Optional[str] = Field(None, alias="top_level_domain")
    geo: Optional[ECSGeo] = None
    as_: Optional[ECSAS] = Field(None, alias="as")
    nat_ip: Optional[str] = Field(None, alias="nat.ip")
    nat_port: Optional[int] = Field(None, alias="nat.port", ge=0, le=65535)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
        return v


class ECSDestination(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=0, le=65535)
    mac: Optional[str] = None
    domain: Optional[str] = None
    bytes: Optional[int] = Field(None, ge=0)
    packets: Optional[int] = Field(None, ge=0)
    registered_domain: Optional[str] = Field(None, alias="registered_domain")
    top_level_domain: Optional[str] = Field(None, alias="top_level_domain")
    geo: Optional[ECSGeo] = None
    as_: Optional[ECSAS] = Field(None, alias="as")
    nat_ip: Optional[str] = Field(None, alias="nat.ip")
    nat_port: Optional[int] = Field(None, alias="nat.port", ge=0, le=65535)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                return None
        return v


class ECSOS(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    family: Optional[str] = None
    full: Optional[str] = None
    kernel: Optional[str] = None
    name: Optional[str] = None
    platform: Optional[str] = None
    type: Optional[str] = None
    version: Optional[str] = None


class ECSHost(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    name: Optional[str] = None
    hostname: Optional[str] = None
    id: Optional[str] = None
    ip: Optional[list[str]] = None
    mac: Optional[list[str]] = None
    domain: Optional[str] = None
    type: Optional[str] = None
    uptime: Optional[int] = None
    architecture: Optional[str] = None
    os: Optional[ECSOS] = None


class ECSUser(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    name: Optional[str] = None
    full_name: Optional[str] = Field(None, alias="full_name")
    domain: Optional[str] = None
    id: Optional[str] = None
    email: Optional[str] = None
    hash: Optional[str] = None
    group: Optional[dict[str, Any]] = None
    roles: Optional[list[str]] = None
    effective: Optional[dict[str, Any]] = None
    target: Optional[dict[str, Any]] = None
    changes: Optional[dict[str, Any]] = None


class ECSProcessParent(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    pid: Optional[int] = None
    name: Optional[str] = None
    executable: Optional[str] = None
    command_line: Optional[str] = Field(None, alias="command_line")
    args: Optional[list[str]] = None
    working_directory: Optional[str] = Field(None, alias="working_directory")
    entity_id: Optional[str] = Field(None, alias="entity_id")


class ECSProcess(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    pid: Optional[int] = None
    name: Optional[str] = None
    executable: Optional[str] = None
    command_line: Optional[str] = Field(None, alias="command_line")
    args: Optional[list[str]] = None
    working_directory: Optional[str] = Field(None, alias="working_directory")
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    exit_code: Optional[int] = Field(None, alias="exit_code")
    title: Optional[str] = None
    thread_id: Optional[int] = Field(None, alias="thread.id")
    entity_id: Optional[str] = Field(None, alias="entity_id")
    parent: Optional[ECSProcessParent] = None
    user: Optional[ECSUser] = None
    hash: Optional[dict[str, str]] = None


class ECSFileHash(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None


class ECSFile(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    name: Optional[str] = None
    path: Optional[str] = None
    directory: Optional[str] = None
    extension: Optional[str] = None
    mime_type: Optional[str] = Field(None, alias="mime_type")
    size: Optional[int] = Field(None, ge=0)
    type: Optional[str] = None
    uid: Optional[str] = None
    gid: Optional[str] = None
    owner: Optional[str] = None
    group: Optional[str] = None
    mode: Optional[str] = None
    inode: Optional[str] = None
    device: Optional[str] = None
    target_path: Optional[str] = Field(None, alias="target_path")
    hash: Optional[ECSFileHash] = None
    created: Optional[datetime] = None
    accessed: Optional[datetime] = None
    mtime: Optional[datetime] = None
    ctime: Optional[datetime] = None


class ECSNetwork(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    protocol: Optional[str] = None
    transport: Optional[str] = None
    type: Optional[str] = None
    application: Optional[str] = None
    direction: Optional[NetworkDirection] = None
    bytes: Optional[int] = Field(None, ge=0)
    packets: Optional[int] = Field(None, ge=0)
    community_id: Optional[str] = Field(None, alias="community_id")
    forwarded_ip: Optional[str] = Field(None, alias="forwarded_ip")
    iana_number: Optional[str] = Field(None, alias="iana_number")
    name: Optional[str] = None
    vlan_id: Optional[str] = Field(None, alias="vlan.id")
    vlan_name: Optional[str] = Field(None, alias="vlan.name")
    inner: Optional[dict[str, Any]] = None


class ECSDNSQuestion(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    name: Optional[str] = None
    type: Optional[str] = None
    class_: Optional[str] = Field(None, alias="class")
    registered_domain: Optional[str] = Field(None, alias="registered_domain")
    subdomain: Optional[str] = None
    top_level_domain: Optional[str] = Field(None, alias="top_level_domain")


class ECSDNSAnswer(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    name: Optional[str] = None
    type: Optional[str] = None
    class_: Optional[str] = Field(None, alias="class")
    data: Optional[str] = None
    ttl: Optional[int] = None


class ECSDNS(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    id: Optional[str] = None
    op_code: Optional[str] = Field(None, alias="op_code")
    type: Optional[str] = None
    response_code: Optional[str] = Field(None, alias="response_code")
    header_flags: Optional[list[str]] = Field(None, alias="header_flags")
    question: Optional[ECSDNSQuestion] = None
    answers: Optional[list[ECSDNSAnswer]] = None
    resolved_ip: Optional[list[str]] = Field(None, alias="resolved_ip")


class ECSHTTPRequestBody(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    bytes: Optional[int] = Field(None, ge=0)
    content: Optional[str] = None


class ECSHTTPRequest(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    method: Optional[str] = None
    bytes: Optional[int] = Field(None, ge=0)
    referrer: Optional[str] = None
    mime_type: Optional[str] = Field(None, alias="mime_type")
    body: Optional[ECSHTTPRequestBody] = None


class ECSHTTPResponseBody(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    bytes: Optional[int] = Field(None, ge=0)
    content: Optional[str] = None


class ECSHTTPResponse(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    status_code: Optional[int] = Field(None, alias="status_code")
    bytes: Optional[int] = Field(None, ge=0)
    mime_type: Optional[str] = Field(None, alias="mime_type")
    body: Optional[ECSHTTPResponseBody] = None


class ECSHTTP(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    version: Optional[str] = None
    request: Optional[ECSHTTPRequest] = None
    response: Optional[ECSHTTPResponse] = None


class ECSURL(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    full: Optional[str] = None
    original: Optional[str] = None
    scheme: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = Field(None, ge=0, le=65535)
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    registered_domain: Optional[str] = Field(None, alias="registered_domain")
    top_level_domain: Optional[str] = Field(None, alias="top_level_domain")
    extension: Optional[str] = None


class ECSRule(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    ruleset: Optional[str] = None
    version: Optional[str] = None
    author: Optional[list[str]] = None
    license: Optional[str] = None
    reference: Optional[str] = None
    uuid: Optional[str] = None


class ECSThreatIndicator(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    type: Optional[str] = None
    description: Optional[str] = None
    provider: Optional[str] = None
    reference: Optional[str] = None
    confidence: Optional[str] = None
    scanner_stats: Optional[int] = Field(None, alias="scanner_stats")
    sightings: Optional[int] = None
    first_seen: Optional[datetime] = Field(None, alias="first_seen")
    last_seen: Optional[datetime] = Field(None, alias="last_seen")
    marking_tlp: Optional[str] = Field(None, alias="marking.tlp")
    ip: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    email_address: Optional[str] = Field(None, alias="email.address")
    url_full: Optional[str] = Field(None, alias="url.full")
    file_hash_sha256: Optional[str] = Field(None, alias="file.hash.sha256")
    file_hash_md5: Optional[str] = Field(None, alias="file.hash.md5")


class ECSThreatTactic(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    id: Optional[str] = None
    name: Optional[str] = None
    reference: Optional[str] = None


class ECSThreatTechnique(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    id: Optional[str] = None
    name: Optional[str] = None
    reference: Optional[str] = None
    subtechnique: Optional[list[dict[str, str]]] = None


class ECSThreat(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    framework: Optional[str] = None
    tactic: Optional[ECSThreatTactic] = None
    technique: Optional[list[ECSThreatTechnique]] = None
    indicator: Optional[ECSThreatIndicator] = None
    group: Optional[dict[str, Any]] = None
    software: Optional[dict[str, Any]] = None


class ECSAgent(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    version: Optional[str] = None
    ephemeral_id: Optional[str] = Field(None, alias="ephemeral_id")


class ECSLog(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    level: Optional[str] = None
    logger: Optional[str] = None
    origin: Optional[dict[str, Any]] = None
    file_path: Optional[str] = Field(None, alias="file.path")
    syslog: Optional[dict[str, Any]] = None


class ECSEvent(BaseModel):
    """Core ECS event metadata."""

    model_config = {"populate_by_name": True, "extra": "allow"}

    kind: Optional[EventKind] = None
    category: Optional[list[EventCategory]] = None
    type: Optional[list[EventType]] = None
    action: Optional[str] = None
    outcome: Optional[EventOutcome] = None
    module: Optional[str] = None
    dataset: Optional[str] = None
    severity: Optional[int] = Field(None, ge=0, le=100)
    risk_score: Optional[float] = Field(None, alias="risk_score", ge=0.0, le=100.0)
    risk_score_norm: Optional[float] = Field(
        None, alias="risk_score_norm", ge=0.0, le=100.0
    )
    id: Optional[str] = None
    code: Optional[str] = None
    provider: Optional[str] = None
    original: Optional[str] = None
    hash: Optional[str] = None
    duration: Optional[int] = None
    sequence: Optional[int] = None
    created: Optional[datetime] = None
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    timezone: Optional[str] = None
    ingested: Optional[datetime] = None
    url: Optional[str] = None
    reason: Optional[str] = None
    reference: Optional[str] = None


class ECSObserver(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    hostname: Optional[str] = None
    ip: Optional[list[str]] = None
    mac: Optional[list[str]] = None
    name: Optional[str] = None
    product: Optional[str] = None
    serial_number: Optional[str] = Field(None, alias="serial_number")
    type: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None


class ECSCloud(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    provider: Optional[str] = None
    account_id: Optional[str] = Field(None, alias="account.id")
    account_name: Optional[str] = Field(None, alias="account.name")
    region: Optional[str] = None
    availability_zone: Optional[str] = Field(None, alias="availability_zone")
    instance_id: Optional[str] = Field(None, alias="instance.id")
    instance_name: Optional[str] = Field(None, alias="instance.name")
    machine_type: Optional[str] = Field(None, alias="machine.type")
    project_id: Optional[str] = Field(None, alias="project.id")


class ECSContainer(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    id: Optional[str] = None
    name: Optional[str] = None
    image_name: Optional[str] = Field(None, alias="image.name")
    image_tag: Optional[str] = Field(None, alias="image.tag")
    runtime: Optional[str] = None
    labels: Optional[dict[str, str]] = None


class ECSError(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    code: Optional[str] = None
    id: Optional[str] = None
    message: Optional[str] = None
    stack_trace: Optional[str] = Field(None, alias="stack_trace")
    type: Optional[str] = None


class ECSService(BaseModel):
    model_config = {"populate_by_name": True, "extra": "allow"}

    id: Optional[str] = None
    name: Optional[str] = None
    type: Optional[str] = None
    version: Optional[str] = None
    environment: Optional[str] = None
    ephemeral_id: Optional[str] = Field(None, alias="ephemeral_id")
    node_name: Optional[str] = Field(None, alias="node.name")
    state: Optional[str] = None


class ECSRelated(BaseModel):
    """Fields for pivoting across events."""

    model_config = {"populate_by_name": True, "extra": "allow"}

    ip: Optional[list[str]] = None
    user: Optional[list[str]] = None
    hash: Optional[list[str]] = None
    hosts: Optional[list[str]] = None


class ECSCyberNest(BaseModel):
    """CyberNest-specific metadata added during pipeline processing."""

    model_config = {"populate_by_name": True, "extra": "allow"}

    event_id: Optional[str] = None
    parser_name: Optional[str] = None
    parse_status: str = "success"
    parse_time: Optional[str] = None
    parse_duration_ms: Optional[float] = None
    parser_version: str = "1.0.0"
    source_name: Optional[str] = None
    agent_id: Optional[str] = None
    ingested_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Top-level ECS Event Document
# ---------------------------------------------------------------------------

class ECSEventDocument(BaseModel):
    """
    Full ECS 8.x event document for CyberNest SIEM pipeline.

    This is the canonical normalized event representation used across
    ingestion, parsing, correlation, indexing, and alerting.
    """

    model_config = {
        "populate_by_name": True,
        "extra": "allow",
        "json_schema_extra": {
            "title": "CyberNest ECS Event",
            "description": "Elastic Common Schema v8.x compatible security event.",
        },
    }

    # --- Base fields -------------------------------------------------------
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        alias="@timestamp",
        description="Event timestamp in UTC.",
    )
    message: Optional[str] = None
    tags: Optional[list[str]] = None
    labels: Optional[dict[str, str]] = None
    ecs_version: Optional[str] = Field(default="8.11.0", alias="ecs.version")

    # --- ECS field sets ----------------------------------------------------
    event: Optional[ECSEvent] = None
    source: Optional[ECSSource] = None
    destination: Optional[ECSDestination] = None
    host: Optional[ECSHost] = None
    user: Optional[ECSUser] = None
    process: Optional[ECSProcess] = None
    file: Optional[ECSFile] = None
    network: Optional[ECSNetwork] = None
    dns: Optional[ECSDNS] = None
    http: Optional[ECSHTTP] = None
    url: Optional[ECSURL] = None
    rule: Optional[ECSRule] = None
    threat: Optional[ECSThreat] = None
    agent: Optional[ECSAgent] = None
    log: Optional[ECSLog] = None
    observer: Optional[ECSObserver] = None
    cloud: Optional[ECSCloud] = None
    container: Optional[ECSContainer] = None
    error: Optional[ECSError] = None
    service: Optional[ECSService] = None
    related: Optional[ECSRelated] = None
    cybernest: Optional[ECSCyberNest] = None

    # --- Raw / extra -------------------------------------------------------
    raw: Optional[str] = None

    # --- Validators --------------------------------------------------------
    @model_validator(mode="before")
    @classmethod
    def coerce_timestamp(cls, values: Any) -> Any:
        """Accept ISO strings for @timestamp and convert to datetime."""
        if isinstance(values, dict):
            ts = values.get("@timestamp") or values.get("timestamp")
            if isinstance(ts, str):
                values["@timestamp"] = datetime.fromisoformat(
                    ts.replace("Z", "+00:00")
                )
        return values

    @field_validator("tags", mode="before")
    @classmethod
    def deduplicate_tags(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is not None:
            return list(dict.fromkeys(v))
        return v

    # --- Helpers -----------------------------------------------------------
    def to_flat_dict(self) -> dict[str, Any]:
        """Flatten nested ECS structure to dot-notation dict for Elasticsearch."""
        result: dict[str, Any] = {}

        def _flatten(prefix: str, obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_key = f"{prefix}.{k}" if prefix else k
                    _flatten(new_key, v)
            elif isinstance(obj, BaseModel):
                for k, v in obj.model_dump(by_alias=True, exclude_none=True).items():
                    new_key = f"{prefix}.{k}" if prefix else k
                    _flatten(new_key, v)
            elif isinstance(obj, list):
                if obj is not None:
                    result[prefix] = obj
            else:
                if obj is not None:
                    result[prefix] = obj

        data = self.model_dump(by_alias=True, exclude_none=True)
        _flatten("", data)
        return result


# ---------------------------------------------------------------------------
# Backward-compatible alias
# ---------------------------------------------------------------------------
CyberNestEvent = ECSEventDocument

"""
CyberNest AWS CloudTrail Parser.

Parses AWS CloudTrail JSON events and maps to ECS fields.
Extracts: eventName, eventSource, userIdentity, sourceIPAddress, requestParameters.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from shared.utils.logger import get_logger
from parser.parsers import register_parser

logger = get_logger("parser.aws_cloudtrail")

# CloudTrail event category mappings based on eventSource
EVENT_SOURCE_CATEGORIES: dict[str, list[str]] = {
    "iam.amazonaws.com": ["iam"],
    "sts.amazonaws.com": ["authentication"],
    "signin.amazonaws.com": ["authentication"],
    "s3.amazonaws.com": ["file"],
    "ec2.amazonaws.com": ["host"],
    "rds.amazonaws.com": ["database"],
    "lambda.amazonaws.com": ["process"],
    "kms.amazonaws.com": ["configuration"],
    "cloudtrail.amazonaws.com": ["configuration"],
    "config.amazonaws.com": ["configuration"],
    "guardduty.amazonaws.com": ["intrusion_detection"],
    "securityhub.amazonaws.com": ["intrusion_detection"],
    "organizations.amazonaws.com": ["iam"],
    "elasticloadbalancing.amazonaws.com": ["network"],
    "cloudfront.amazonaws.com": ["network"],
    "route53.amazonaws.com": ["network"],
    "sqs.amazonaws.com": ["process"],
    "sns.amazonaws.com": ["process"],
    "dynamodb.amazonaws.com": ["database"],
}

# Event type mapping based on event name patterns
EVENT_TYPE_PATTERNS: list[tuple[str, list[str]]] = [
    ("Create", ["creation"]),
    ("Put", ["creation"]),
    ("Run", ["start"]),
    ("Start", ["start"]),
    ("Launch", ["start"]),
    ("Delete", ["deletion"]),
    ("Remove", ["deletion"]),
    ("Terminate", ["end"]),
    ("Stop", ["end"]),
    ("Update", ["change"]),
    ("Modify", ["change"]),
    ("Attach", ["change"]),
    ("Detach", ["change"]),
    ("Add", ["change"]),
    ("Set", ["change"]),
    ("Enable", ["change"]),
    ("Disable", ["change"]),
    ("Authorize", ["allowed"]),
    ("Revoke", ["denied"]),
    ("Describe", ["info"]),
    ("Get", ["info"]),
    ("List", ["info"]),
    ("Lookup", ["info"]),
    ("AssumeRole", ["info"]),
    ("ConsoleLogin", ["start"]),
]


def _is_cloudtrail(raw_data: Any) -> bool:
    """Detect AWS CloudTrail JSON format."""
    if isinstance(raw_data, dict):
        data = raw_data
    elif isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            return False
    else:
        return False

    # CloudTrail events have eventVersion and eventSource
    return (
        "eventVersion" in data and "eventSource" in data
    ) or (
        "Records" in data and isinstance(data.get("Records"), list)
    )


def _parse_user_identity(identity: dict[str, Any]) -> dict[str, Any]:
    """Extract user info from CloudTrail userIdentity."""
    user: dict[str, Any] = {}
    id_type = identity.get("type", "")

    if id_type == "Root":
        user["name"] = "root"
        user["id"] = identity.get("accountId", "")
    elif id_type == "IAMUser":
        user["name"] = identity.get("userName", "")
        user["id"] = identity.get("principalId", "")
    elif id_type == "AssumedRole":
        session = identity.get("sessionContext", {}).get("sessionIssuer", {})
        user["name"] = session.get("userName", identity.get("principalId", ""))
        user["id"] = identity.get("principalId", "")
        user["roles"] = [session.get("arn", "")]
    elif id_type == "FederatedUser":
        user["name"] = identity.get("principalId", "").split(":")[-1]
        user["id"] = identity.get("principalId", "")
    elif id_type == "AWSService":
        user["name"] = identity.get("invokedBy", "aws-service")
        user["id"] = "aws-service"
    elif id_type == "AWSAccount":
        user["name"] = identity.get("accountId", "")
        user["id"] = identity.get("accountId", "")
    else:
        user["name"] = identity.get("principalId", identity.get("userName", "unknown"))
        user["id"] = identity.get("principalId", "")

    arn = identity.get("arn", "")
    if arn:
        user["full_name"] = arn

    return user


def _get_event_types(event_name: str) -> list[str]:
    """Determine ECS event types from CloudTrail eventName."""
    for pattern, types in EVENT_TYPE_PATTERNS:
        if pattern in event_name:
            return types
    return ["info"]


def _parse_single_event(data: dict[str, Any]) -> dict[str, Any]:
    """Parse a single CloudTrail event record."""
    event_name = data.get("eventName", "")
    event_source = data.get("eventSource", "")
    event_time = data.get("eventTime", "")
    source_ip = data.get("sourceIPAddress", "")
    user_agent = data.get("userAgent", "")
    user_identity = data.get("userIdentity", {})
    request_params = data.get("requestParameters")
    response_elements = data.get("responseElements")
    error_code = data.get("errorCode")
    error_message = data.get("errorMessage")
    aws_region = data.get("awsRegion", "")
    account_id = user_identity.get("accountId", "")
    event_id = data.get("eventID", "")
    read_only = data.get("readOnly")
    event_type = data.get("eventType", "AwsApiCall")
    management_event = data.get("managementEvent")
    resources = data.get("resources", [])
    recipient_account_id = data.get("recipientAccountId", "")

    # Parse timestamp
    ts = event_time
    if ts:
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat() + "Z"
        except (ValueError, TypeError):
            pass

    # Determine outcome
    outcome = "failure" if error_code else "success"

    # Determine categories
    service = event_source.split(".")[0] if event_source else "aws"
    categories = EVENT_SOURCE_CATEGORIES.get(event_source, ["cloud"])

    # Determine event types
    event_types = _get_event_types(event_name)

    # Parse user identity
    user = _parse_user_identity(user_identity)

    # Determine severity
    severity = 20  # default: info
    if error_code:
        severity = 50
    if event_name in ("ConsoleLogin", "AssumeRole"):
        severity = 40
    if "Delete" in event_name or "Terminate" in event_name:
        severity = 60
    if event_name in ("StopLogging", "DeleteTrail", "PutBucketPolicy"):
        severity = 80

    ecs: dict[str, Any] = {
        "@timestamp": ts or datetime.utcnow().isoformat() + "Z",
        "message": f"CloudTrail: {event_name} by {user.get('name', 'unknown')} ({event_source})",
        "raw": json.dumps(data, default=str),
        "event": {
            "kind": "event",
            "category": categories,
            "type": event_types,
            "action": event_name,
            "outcome": outcome,
            "severity": severity,
            "id": event_id,
            "code": error_code,
            "reason": error_message,
            "module": "aws",
            "dataset": f"aws.cloudtrail",
            "provider": event_source,
        },
        "cloud": {
            "provider": "aws",
            "region": aws_region,
            "account": {"id": account_id},
        },
        "user": user,
        "source": {
            "ip": source_ip if source_ip and not source_ip.endswith(".amazonaws.com") else None,
            "domain": source_ip if source_ip and source_ip.endswith(".amazonaws.com") else None,
        },
        "user_agent": {
            "original": user_agent if user_agent else None,
        },
    }

    # Add error info
    if error_code:
        ecs["error"] = {
            "code": error_code,
            "message": error_message,
        }

    # Add resource info
    if resources:
        resource_arns = [r.get("ARN", "") for r in resources if r.get("ARN")]
        resource_types = [r.get("type", "") for r in resources if r.get("type")]
        ecs["cloud"]["resource"] = {
            "arns": resource_arns,
            "types": resource_types,
        }

    # Store CloudTrail-specific fields
    ecs["aws"] = {
        "cloudtrail": {
            "event_type": event_type,
            "event_version": data.get("eventVersion"),
            "read_only": read_only,
            "management_event": management_event,
            "recipient_account_id": recipient_account_id,
            "request_parameters": request_params,
            "response_elements": response_elements,
            "additional_event_data": data.get("additionalEventData"),
            "service_event_details": data.get("serviceEventDetails"),
            "shared_event_id": data.get("sharedEventID"),
            "vpc_endpoint_id": data.get("vpcEndpointId"),
            "resources": resources,
        },
    }

    # Related fields
    related_ips: list[str] = []
    related_users: list[str] = []
    if source_ip and not source_ip.endswith(".amazonaws.com"):
        related_ips.append(source_ip)
    if user.get("name"):
        related_users.append(user["name"])

    related: dict[str, list[str]] = {}
    if related_ips:
        related["ip"] = list(set(related_ips))
    if related_users:
        related["user"] = list(set(related_users))
    if related:
        ecs["related"] = related

    ecs["cybernest"] = {
        "parser_name": "aws_cloudtrail",
        "parse_status": "success",
        "parser_version": "1.0.0",
    }

    return ecs


@register_parser("aws_cloudtrail", detector=_is_cloudtrail, priority=14)
def parse_aws_cloudtrail(raw_data: Any) -> dict[str, Any]:
    """Parse an AWS CloudTrail event to ECS format.

    Handles both single events and Records arrays.
    For Records arrays, returns the first event (caller should iterate).
    """
    if isinstance(raw_data, str):
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid CloudTrail JSON: {exc}") from exc
    elif isinstance(raw_data, dict):
        data = raw_data
    else:
        raise ValueError(f"Unsupported CloudTrail data type: {type(raw_data)}")

    # Handle Records array wrapper
    if "Records" in data and isinstance(data["Records"], list):
        if not data["Records"]:
            raise ValueError("Empty CloudTrail Records array")
        return _parse_single_event(data["Records"][0])

    return _parse_single_event(data)


def parse_cloudtrail_records(raw_data: Any) -> list[dict[str, Any]]:
    """Parse all records from a CloudTrail log file.

    Returns a list of ECS events, one per CloudTrail record.
    """
    if isinstance(raw_data, str):
        data = json.loads(raw_data)
    elif isinstance(raw_data, dict):
        data = raw_data
    else:
        raise ValueError(f"Unsupported data type: {type(raw_data)}")

    records = data.get("Records", [data])
    return [_parse_single_event(r) for r in records]

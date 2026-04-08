"""
CyberNest Correlator — Rule Engine Tests.

Tests:
  - test_rule_match_equals
  - test_rule_match_contains
  - test_rule_match_regex
  - test_rule_no_match
  - test_threshold_rule (with mocked Redis)
  - test_sigma_rule_load
"""

from __future__ import annotations

import asyncio
import sys
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure the project root is on sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from correlator.engine.rule_engine import RuleEngine, DetectionRule
from correlator.engine.sigma_loader import SigmaLoader, SigmaRule


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine() -> RuleEngine:
    """Create a RuleEngine with no Redis (sync-only mode)."""
    return RuleEngine(redis_client=None)


@pytest.fixture
def sample_event() -> dict[str, Any]:
    """A sample ECS event for testing."""
    return {
        "@timestamp": "2025-04-07T14:30:00Z",
        "message": "Failed password for admin from 10.0.0.5 port 22 ssh2",
        "event": {
            "category": ["authentication"],
            "type": ["start"],
            "outcome": "failure",
            "action": "ssh_failed",
        },
        "source": {
            "ip": "10.0.0.5",
            "port": 54321,
        },
        "destination": {
            "ip": "192.168.1.100",
            "port": 22,
        },
        "user": {
            "name": "admin",
        },
        "host": {
            "hostname": "webserver01",
            "os": {
                "platform": "linux",
            },
        },
        "process": {
            "name": "sshd",
            "command_line": "sshd: admin [preauth]",
        },
        "cybernest": {
            "event_id": "evt-test-001",
        },
    }


@pytest.fixture
def equals_rule_data() -> dict[str, Any]:
    return {
        "id": "TEST-EQUALS-001",
        "name": "Test Equals Rule",
        "description": "Matches failed authentication events.",
        "level": "medium",
        "category": "authentication",
        "mitre_tactic": "TA0006",
        "mitre_technique": ["T1110"],
        "enabled": True,
        "conditions": {
            "logic": "and",
            "fields": [
                {"field": "event.outcome", "operator": "equals", "value": "failure"},
                {"field": "user.name", "operator": "equals", "value": "admin"},
            ],
        },
    }


@pytest.fixture
def contains_rule_data() -> dict[str, Any]:
    return {
        "id": "TEST-CONTAINS-001",
        "name": "Test Contains Rule",
        "description": "Matches events containing ssh in the message.",
        "level": "low",
        "category": "authentication",
        "mitre_tactic": "TA0006",
        "mitre_technique": ["T1110"],
        "enabled": True,
        "conditions": {
            "logic": "and",
            "fields": [
                {"field": "message", "operator": "contains", "value": "ssh"},
                {"field": "event.outcome", "operator": "equals", "value": "failure"},
            ],
        },
    }


@pytest.fixture
def regex_rule_data() -> dict[str, Any]:
    return {
        "id": "TEST-REGEX-001",
        "name": "Test Regex Rule",
        "description": "Matches events with IP pattern in message.",
        "level": "high",
        "category": "authentication",
        "mitre_tactic": "TA0006",
        "mitre_technique": ["T1110"],
        "enabled": True,
        "conditions": {
            "logic": "and",
            "fields": [
                {"field": "message", "operator": "regex", "value": r"\d+\.\d+\.\d+\.\d+"},
                {"field": "process.name", "operator": "equals", "value": "sshd"},
            ],
        },
    }


@pytest.fixture
def no_match_rule_data() -> dict[str, Any]:
    return {
        "id": "TEST-NOMATCH-001",
        "name": "Test No Match Rule",
        "description": "Should not match the sample event.",
        "level": "high",
        "category": "malware",
        "mitre_tactic": "TA0002",
        "mitre_technique": ["T1059"],
        "enabled": True,
        "conditions": {
            "logic": "and",
            "fields": [
                {"field": "event.outcome", "operator": "equals", "value": "success"},
                {"field": "process.name", "operator": "equals", "value": "powershell.exe"},
            ],
        },
    }


@pytest.fixture
def threshold_rule_data() -> dict[str, Any]:
    return {
        "id": "TEST-THRESH-001",
        "name": "Test Threshold Rule",
        "description": "Fires only after threshold is met.",
        "level": "high",
        "category": "authentication",
        "mitre_tactic": "TA0006",
        "mitre_technique": ["T1110"],
        "enabled": True,
        "conditions": {
            "logic": "and",
            "fields": [
                {"field": "event.outcome", "operator": "equals", "value": "failure"},
            ],
        },
        "threshold": {
            "field": "user.name",
            "count": 5,
            "timeframe": 60,
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRuleMatchEquals:
    """Test that equals operator matches correctly."""

    def test_rule_match_equals(
        self, engine: RuleEngine, equals_rule_data: dict, sample_event: dict,
    ) -> None:
        engine.load_rule_from_dict(equals_rule_data)
        alerts = engine.match_sync(sample_event)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_id"] == "TEST-EQUALS-001"
        assert alert["severity"] == "medium"
        assert alert["username"] == "admin"
        assert alert["source_ip"] == "10.0.0.5"
        assert "T1110" in alert["mitre_technique"]


class TestRuleMatchContains:
    """Test that contains operator matches correctly."""

    def test_rule_match_contains(
        self, engine: RuleEngine, contains_rule_data: dict, sample_event: dict,
    ) -> None:
        engine.load_rule_from_dict(contains_rule_data)
        alerts = engine.match_sync(sample_event)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_id"] == "TEST-CONTAINS-001"


class TestRuleMatchRegex:
    """Test that regex operator matches correctly."""

    def test_rule_match_regex(
        self, engine: RuleEngine, regex_rule_data: dict, sample_event: dict,
    ) -> None:
        engine.load_rule_from_dict(regex_rule_data)
        alerts = engine.match_sync(sample_event)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["rule_id"] == "TEST-REGEX-001"
        assert alert["severity"] == "high"


class TestRuleNoMatch:
    """Test that rules do not match when conditions are not met."""

    def test_rule_no_match(
        self, engine: RuleEngine, no_match_rule_data: dict, sample_event: dict,
    ) -> None:
        engine.load_rule_from_dict(no_match_rule_data)
        alerts = engine.match_sync(sample_event)
        assert len(alerts) == 0


class TestThresholdRule:
    """Test threshold-based rule with mocked Redis."""

    @pytest.mark.asyncio
    async def test_threshold_rule(
        self, threshold_rule_data: dict, sample_event: dict,
    ) -> None:
        # Create a mock Redis client
        mock_redis = AsyncMock()

        # Mock pipeline that returns: zadd result, zremrangebyscore result,
        # zcard result (below threshold), expire result
        mock_pipeline = AsyncMock()
        mock_pipeline.zadd = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zremrangebyscore = MagicMock(return_value=mock_pipeline)
        mock_pipeline.zcard = MagicMock(return_value=mock_pipeline)
        mock_pipeline.expire = MagicMock(return_value=mock_pipeline)

        # First call: below threshold (count=3)
        mock_pipeline.execute = AsyncMock(return_value=[1, 0, 3, True])
        mock_redis.pipeline = MagicMock(return_value=mock_pipeline)

        engine = RuleEngine(redis_client=mock_redis)
        engine.load_rule_from_dict(threshold_rule_data)

        # Should NOT alert when below threshold
        alerts = await engine.match(sample_event)
        assert len(alerts) == 0

        # Second call: at threshold (count=5)
        mock_pipeline.execute = AsyncMock(return_value=[1, 0, 5, True])

        alerts = await engine.match(sample_event)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "TEST-THRESH-001"

        # Third call: above threshold (count=10)
        mock_pipeline.execute = AsyncMock(return_value=[1, 0, 10, True])

        alerts = await engine.match(sample_event)
        assert len(alerts) == 1


class TestSigmaRuleLoad:
    """Test Sigma rule parsing and conversion."""

    def test_sigma_rule_load(self) -> None:
        sigma_data = {
            "title": "Mimikatz Command Line Usage",
            "id": "a642964e-bead-4bed-8910-1bb4d63e3b4d",
            "status": "test",
            "description": "Detects Mimikatz command line usage",
            "level": "critical",
            "tags": [
                "attack.credential_access",
                "attack.t1003.001",
            ],
            "logsource": {
                "category": "process_creation",
                "product": "windows",
            },
            "detection": {
                "selection": {
                    "CommandLine|contains": [
                        "mimikatz",
                        "sekurlsa",
                    ],
                },
                "condition": "selection",
            },
            "falsepositives": [
                "Legitimate admin tools",
            ],
        }

        loader = SigmaLoader()
        internal = loader.load_single(sigma_data)

        assert internal["name"] == "Mimikatz Command Line Usage"
        assert internal["level"] == "critical"
        assert internal["mitre_tactic"] == "TA0006"
        assert "T1003.001" in internal["mitre_technique"]
        assert internal["source"] == "sigma"
        assert internal["enabled"] is True

        # Verify conditions were parsed
        conditions = internal["conditions"]
        assert conditions is not None
        fields = conditions.get("fields", [])
        assert len(fields) > 0

        # Verify the loader tracked the rule
        assert len(loader.sigma_rules) == 1
        assert len(loader.internal_rules) == 1

    def test_sigma_condition_and_not(self) -> None:
        """Test 'selection AND NOT filter' condition parsing."""
        sigma_data = {
            "title": "Suspicious Process",
            "id": "b742964e-bead-0000-0000-1bb4d63e3b4d",
            "status": "test",
            "description": "Test rule",
            "level": "medium",
            "tags": ["attack.execution"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "ParentImage|endswith": "\\explorer.exe",
                },
                "filter": {
                    "Image|endswith": "\\chrome.exe",
                },
                "condition": "selection and not filter",
            },
        }

        loader = SigmaLoader()
        internal = loader.load_single(sigma_data)

        conditions = internal["conditions"]
        fields = conditions.get("fields", [])
        # Should have both selection (endswith) and negated filter
        assert len(fields) >= 2

    def test_sigma_1_of_selection(self) -> None:
        """Test '1 of selection*' condition parsing."""
        sigma_data = {
            "title": "Multiple Selections",
            "id": "c842964e-0000-0000-0000-1bb4d63e3b4d",
            "status": "test",
            "description": "Test rule with 1 of",
            "level": "high",
            "tags": [],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection1": {"Image|endswith": "\\cmd.exe"},
                "selection2": {"Image|endswith": "\\powershell.exe"},
                "condition": "1 of selection*",
            },
        }

        loader = SigmaLoader()
        internal = loader.load_single(sigma_data)

        conditions = internal["conditions"]
        assert conditions["logic"] == "or"
        assert len(conditions["fields"]) >= 2


class TestRuleLoading:
    """Test loading rules from YAML files."""

    def test_load_rules_from_directory(self) -> None:
        engine = RuleEngine(redis_client=None)
        rules_dir = str(Path(__file__).resolve().parent.parent / "rules")
        count = engine.load_rules_from_directory(rules_dir)
        assert count > 0
        assert len(engine.rules) > 0

        # Verify all rules have required fields
        for rule in engine.rules:
            assert rule.id, f"Rule missing id: {rule}"
            assert rule.name, f"Rule missing name: {rule}"
            assert rule.level in (
                "informational", "low", "medium", "high", "critical",
            ), f"Invalid level for {rule.id}: {rule.level}"

    def test_load_specific_rule_counts(self) -> None:
        """Verify expected number of rules per category."""
        engine = RuleEngine(redis_client=None)
        rules_dir = str(Path(__file__).resolve().parent.parent / "rules")
        engine.load_rules_from_directory(rules_dir)

        # Count by prefix
        counts: dict[str, int] = {}
        for rule in engine.rules:
            prefix = rule.id.rsplit("-", 1)[0] if "-" in rule.id else rule.id
            counts[prefix] = counts.get(prefix, 0) + 1

        # Windows authentication: 10 rules
        assert counts.get("CN-WIN-AUTH", 0) == 10
        # Windows credential access: 9 rules
        assert counts.get("CN-WIN-CRED", 0) == 9
        # Windows privilege escalation: 7 rules
        assert counts.get("CN-WIN-PRIV", 0) == 7
        # Windows execution: 7 rules
        assert counts.get("CN-WIN-EXEC", 0) == 7
        # Linux authentication: 7 rules
        assert counts.get("CN-LNX-AUTH", 0) == 7
        # Linux persistence: 7 rules
        assert counts.get("CN-LNX-PERS", 0) == 7
        # Network discovery: 3 rules
        assert counts.get("CN-NET-DISC", 0) == 3
        # Network C2: 5 rules
        assert counts.get("CN-NET-C2", 0) == 5
        # Cloud AWS: 6 rules
        assert counts.get("CN-CLD-AWS", 0) == 6

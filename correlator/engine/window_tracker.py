"""
CyberNest Redis-backed Sliding Window Tracker.

Provides time-windowed counters, sequence tracking, and unique-value tracking
using Redis sorted sets.  Includes 10 built-in sliding-window detection rules
for common attack patterns.

Built-in rules:
  1. brute_force          – >5 failed_login in 60s per user+ip
  2. password_spray       – >20 failed in 60s, >5 unique users
  3. port_scan            – >20 unique dest ports in 30s
  4. host_sweep           – >15 unique dest IPs in 60s
  5. lateral_movement     – >3 unique dest IPs in 300s with logon
  6. data_exfiltration    – >100MB outbound in 300s
  7. c2_beaconing         – regular HTTP intervals, CoV < 0.1
  8. dns_tunneling        – long subdomains >50 chars, >10 in 60s
  9. impossible_travel    – same user different country <7200s
 10. privilege_escalation_chain – failed->success->admin_group in 600s
"""

from __future__ import annotations

import statistics
import time
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from shared.utils.logger import get_logger

logger = get_logger("correlator")

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "brute_force": "high",
    "password_spray": "critical",
    "port_scan": "high",
    "host_sweep": "high",
    "lateral_movement": "critical",
    "data_exfiltration": "critical",
    "c2_beaconing": "critical",
    "dns_tunneling": "high",
    "impossible_travel": "critical",
    "privilege_escalation_chain": "critical",
}


# ---------------------------------------------------------------------------
# Core sliding-window primitives
# ---------------------------------------------------------------------------

class WindowTracker:
    """Redis-backed sliding window tracker using sorted sets."""

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    async def increment_and_check(
        self, key: str, window_seconds: int, threshold: int,
    ) -> bool:
        """Add an entry to the sliding window and check if threshold is met.

        Uses a Redis sorted set where the score is the timestamp.
        Entries older than *window_seconds* are pruned on every call.

        Returns True if the count within the window >= threshold.
        """
        now = time.time()
        member = f"{uuid4().hex}:{now}"

        pipe = self._redis.pipeline()
        pipe.zadd(key, {member: now})
        pipe.zremrangebyscore(key, "-inf", now - window_seconds)
        pipe.zcard(key)
        pipe.expire(key, window_seconds * 2)
        results = await pipe.execute()

        current_count: int = results[2]
        return current_count >= threshold

    async def track_sequence(
        self, sequence_key: str, event_type: str, window_seconds: int,
    ) -> list[str]:
        """Track an ordered sequence of event types within a window.

        Returns the current sequence of event types within the window.
        """
        now = time.time()
        member = f"{event_type}:{now}:{uuid4().hex[:8]}"

        pipe = self._redis.pipeline()
        pipe.zadd(sequence_key, {member: now})
        pipe.zremrangebyscore(sequence_key, "-inf", now - window_seconds)
        pipe.zrangebyscore(sequence_key, now - window_seconds, "+inf")
        pipe.expire(sequence_key, window_seconds * 2)
        results = await pipe.execute()

        raw_members: list[bytes | str] = results[2]
        sequence: list[str] = []
        for m in raw_members:
            decoded = m.decode("utf-8") if isinstance(m, bytes) else str(m)
            event_part = decoded.split(":")[0]
            sequence.append(event_part)

        return sequence

    async def track_unique_values(
        self, key: str, value: str, window_seconds: int, threshold: int,
    ) -> bool:
        """Track unique values in a sliding window.

        Uses a sorted set where each unique value is a member (not duplicated).
        Returns True when the number of unique values >= threshold.
        """
        now = time.time()

        pipe = self._redis.pipeline()
        # Use the value itself as the member so duplicates are ignored
        pipe.zadd(key, {value: now})
        pipe.zremrangebyscore(key, "-inf", now - window_seconds)
        pipe.zcard(key)
        pipe.expire(key, window_seconds * 2)
        results = await pipe.execute()

        unique_count: int = results[2]
        return unique_count >= threshold

    async def get_window_members(
        self, key: str, window_seconds: int,
    ) -> list[str]:
        """Return all members within the current window."""
        now = time.time()
        raw = await self._redis.zrangebyscore(key, now - window_seconds, "+inf")
        return [m.decode("utf-8") if isinstance(m, bytes) else str(m) for m in raw]

    async def get_window_scores(
        self, key: str, window_seconds: int,
    ) -> list[tuple[str, float]]:
        """Return (member, score) pairs within the current window."""
        now = time.time()
        raw = await self._redis.zrangebyscore(
            key, now - window_seconds, "+inf", withscores=True,
        )
        results: list[tuple[str, float]] = []
        for member, score in raw:
            decoded = member.decode("utf-8") if isinstance(member, bytes) else str(member)
            results.append((decoded, float(score)))
        return results

    async def add_bytes_counter(
        self, key: str, byte_count: int, window_seconds: int,
    ) -> int:
        """Increment a byte counter in a sliding window and return total bytes."""
        now = time.time()
        member = f"{byte_count}:{now}:{uuid4().hex[:8]}"

        pipe = self._redis.pipeline()
        pipe.zadd(key, {member: now})
        pipe.zremrangebyscore(key, "-inf", now - window_seconds)
        pipe.zrangebyscore(key, now - window_seconds, "+inf")
        pipe.expire(key, window_seconds * 2)
        results = await pipe.execute()

        raw_members: list[bytes | str] = results[2]
        total_bytes = 0
        for m in raw_members:
            decoded = m.decode("utf-8") if isinstance(m, bytes) else str(m)
            try:
                total_bytes += int(decoded.split(":")[0])
            except (ValueError, IndexError):
                pass

        return total_bytes


# ---------------------------------------------------------------------------
# Built-in sliding window rules
# ---------------------------------------------------------------------------

class SlidingWindowRules:
    """10 built-in sliding window detection rules."""

    def __init__(self, redis_client: Any) -> None:
        self._tracker = WindowTracker(redis_client)
        self._redis = redis_client

    async def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Run all built-in sliding window rules against an event.

        Returns a list of alert dicts for any rule that fires.
        """
        alerts: list[dict[str, Any]] = []

        checks = [
            self._check_brute_force,
            self._check_password_spray,
            self._check_port_scan,
            self._check_host_sweep,
            self._check_lateral_movement,
            self._check_data_exfiltration,
            self._check_c2_beaconing,
            self._check_dns_tunneling,
            self._check_impossible_travel,
            self._check_privilege_escalation_chain,
        ]

        for check in checks:
            try:
                alert = await check(event)
                if alert is not None:
                    alerts.append(alert)
            except Exception:
                logger.exception("sliding window check failed", check=check.__name__)

        return alerts

    # -- Helpers -----------------------------------------------------------

    def _get_flat(self, event: dict[str, Any], dotted_key: str) -> Any:
        """Resolve a dotted key path from a nested dict."""
        parts = dotted_key.split(".")
        current: Any = event
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
            if current is None:
                return None
        return current

    def _build_alert(
        self,
        rule_name: str,
        rule_id: str,
        title: str,
        description: str,
        event: dict[str, Any],
        mitre_tactic: str = "",
        mitre_technique: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "alert_id": uuid4().hex,
            "rule_id": rule_id,
            "rule_name": title,
            "severity": SEVERITY_MAP.get(rule_name, "high"),
            "status": "new",
            "title": f"[{rule_id}] {title}",
            "description": description,
            "source_ip": self._get_flat(event, "source.ip"),
            "destination_ip": self._get_flat(event, "destination.ip"),
            "username": self._get_flat(event, "user.name"),
            "hostname": self._get_flat(event, "host.hostname") or self._get_flat(event, "host.name"),
            "raw_log": self._get_flat(event, "raw") or self._get_flat(event, "message"),
            "parsed_event": event,
            "event_ids": [self._get_flat(event, "cybernest.event_id") or uuid4().hex],
            "event_count": 1,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique or [],
            "risk_score": 75.0 if SEVERITY_MAP.get(rule_name) == "high" else 95.0,
            "category": rule_name,
            "created_at": now,
            "updated_at": now,
        }

    # -- Rule 1: Brute Force -----------------------------------------------

    async def _check_brute_force(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Brute force: >5 failed_login in 60s per user+ip."""
        outcome = self._get_flat(event, "event.outcome")
        action = self._get_flat(event, "event.action")

        if outcome != "failure":
            return None
        categories = self._get_flat(event, "event.category") or []
        if isinstance(categories, str):
            categories = [categories]
        if "authentication" not in categories and action not in ("logon-failed", "failed_login", "ssh_failed"):
            return None

        user = self._get_flat(event, "user.name") or "unknown"
        src_ip = self._get_flat(event, "source.ip") or "unknown"
        key = f"cn:sw:brute_force:{user}:{src_ip}"

        triggered = await self._tracker.increment_and_check(key, 60, 5)
        if triggered:
            return self._build_alert(
                "brute_force", "CN-SW-BF-001",
                "Brute Force Attack Detected",
                f"More than 5 failed login attempts for user '{user}' from {src_ip} within 60 seconds.",
                event,
                mitre_tactic="TA0006",
                mitre_technique=["T1110"],
            )
        return None

    # -- Rule 2: Password Spray --------------------------------------------

    async def _check_password_spray(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Password spray: >20 failed in 60s with >5 unique users."""
        outcome = self._get_flat(event, "event.outcome")
        if outcome != "failure":
            return None
        categories = self._get_flat(event, "event.category") or []
        if isinstance(categories, str):
            categories = [categories]
        if "authentication" not in categories:
            return None

        src_ip = self._get_flat(event, "source.ip") or "unknown"
        user = self._get_flat(event, "user.name") or "unknown"

        count_key = f"cn:sw:pwd_spray:count:{src_ip}"
        user_key = f"cn:sw:pwd_spray:users:{src_ip}"

        count_met = await self._tracker.increment_and_check(count_key, 60, 20)
        unique_users_met = await self._tracker.track_unique_values(user_key, user, 60, 5)

        if count_met and unique_users_met:
            return self._build_alert(
                "password_spray", "CN-SW-PS-001",
                "Password Spray Attack Detected",
                f"More than 20 failed logins from {src_ip} targeting 5+ unique users within 60 seconds.",
                event,
                mitre_tactic="TA0006",
                mitre_technique=["T1110.003"],
            )
        return None

    # -- Rule 3: Port Scan -------------------------------------------------

    async def _check_port_scan(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Port scan: >20 unique destination ports in 30s from same source."""
        dest_port = self._get_flat(event, "destination.port")
        if dest_port is None:
            return None

        src_ip = self._get_flat(event, "source.ip") or "unknown"
        key = f"cn:sw:port_scan:{src_ip}"

        triggered = await self._tracker.track_unique_values(key, str(dest_port), 30, 20)
        if triggered:
            return self._build_alert(
                "port_scan", "CN-SW-PS-002",
                "Port Scan Detected",
                f"Source {src_ip} contacted more than 20 unique destination ports within 30 seconds.",
                event,
                mitre_tactic="TA0007",
                mitre_technique=["T1046"],
            )
        return None

    # -- Rule 4: Host Sweep ------------------------------------------------

    async def _check_host_sweep(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Host sweep: >15 unique destination IPs in 60s from same source."""
        dest_ip = self._get_flat(event, "destination.ip")
        if dest_ip is None:
            return None

        src_ip = self._get_flat(event, "source.ip") or "unknown"
        key = f"cn:sw:host_sweep:{src_ip}"

        triggered = await self._tracker.track_unique_values(key, dest_ip, 60, 15)
        if triggered:
            return self._build_alert(
                "host_sweep", "CN-SW-HS-001",
                "Host Sweep Detected",
                f"Source {src_ip} contacted more than 15 unique destination IPs within 60 seconds.",
                event,
                mitre_tactic="TA0007",
                mitre_technique=["T1018"],
            )
        return None

    # -- Rule 5: Lateral Movement ------------------------------------------

    async def _check_lateral_movement(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Lateral movement: >3 unique dest IPs in 300s with logon events."""
        action = self._get_flat(event, "event.action") or ""
        outcome = self._get_flat(event, "event.outcome")
        categories = self._get_flat(event, "event.category") or []
        if isinstance(categories, str):
            categories = [categories]

        is_logon = (
            "authentication" in categories
            and outcome == "success"
        ) or action in ("logon", "logged-on", "ssh_login", "remote_login")

        if not is_logon:
            return None

        user = self._get_flat(event, "user.name") or "unknown"
        dest_ip = self._get_flat(event, "destination.ip")
        if dest_ip is None:
            dest_ip = self._get_flat(event, "host.ip")
            if isinstance(dest_ip, list) and dest_ip:
                dest_ip = dest_ip[0]
        if dest_ip is None:
            return None

        key = f"cn:sw:lateral:{user}"
        triggered = await self._tracker.track_unique_values(key, str(dest_ip), 300, 3)
        if triggered:
            return self._build_alert(
                "lateral_movement", "CN-SW-LM-001",
                "Potential Lateral Movement Detected",
                f"User '{user}' authenticated to 3+ unique hosts within 300 seconds.",
                event,
                mitre_tactic="TA0008",
                mitre_technique=["T1021"],
            )
        return None

    # -- Rule 6: Data Exfiltration -----------------------------------------

    async def _check_data_exfiltration(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Data exfiltration: >100MB outbound in 300s."""
        direction = self._get_flat(event, "network.direction")
        if direction not in ("outbound", "egress", "external"):
            return None

        out_bytes = self._get_flat(event, "source.bytes") or self._get_flat(event, "network.bytes")
        if out_bytes is None:
            return None
        try:
            out_bytes = int(out_bytes)
        except (ValueError, TypeError):
            return None

        src_ip = self._get_flat(event, "source.ip") or "unknown"
        key = f"cn:sw:exfil:{src_ip}"
        threshold_bytes = 100 * 1024 * 1024  # 100 MB

        total = await self._tracker.add_bytes_counter(key, out_bytes, 300)
        if total >= threshold_bytes:
            return self._build_alert(
                "data_exfiltration", "CN-SW-EX-001",
                "Potential Data Exfiltration Detected",
                f"Source {src_ip} transferred {total / (1024*1024):.1f} MB outbound in 300 seconds (threshold: 100 MB).",
                event,
                mitre_tactic="TA0010",
                mitre_technique=["T1048"],
            )
        return None

    # -- Rule 7: C2 Beaconing ---------------------------------------------

    async def _check_c2_beaconing(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """C2 beaconing: regular HTTP intervals with CoV < 0.1."""
        protocol = self._get_flat(event, "network.protocol")
        http_method = self._get_flat(event, "http.request.method")
        if protocol not in ("http", "https") and http_method is None:
            return None

        dest_ip = self._get_flat(event, "destination.ip")
        src_ip = self._get_flat(event, "source.ip") or "unknown"
        if dest_ip is None:
            return None

        key = f"cn:sw:beacon:{src_ip}:{dest_ip}"
        now = time.time()

        # Store timestamp entries
        pipe = self._redis.pipeline()
        pipe.zadd(key, {f"{now}:{uuid4().hex[:8]}": now})
        pipe.zremrangebyscore(key, "-inf", now - 3600)
        pipe.zrangebyscore(key, now - 3600, "+inf", withscores=True)
        pipe.expire(key, 7200)
        results = await pipe.execute()

        entries = results[2]
        if len(entries) < 10:
            return None

        # Extract timestamps and compute intervals
        timestamps = sorted([float(score) for _, score in entries])
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            return None

        mean_interval = statistics.mean(intervals)
        if mean_interval < 1.0:
            return None  # Too fast, probably normal traffic

        try:
            stdev = statistics.stdev(intervals)
            cov = stdev / mean_interval if mean_interval > 0 else 1.0
        except statistics.StatisticsError:
            return None

        if cov < 0.1:
            return self._build_alert(
                "c2_beaconing", "CN-SW-C2-001",
                "C2 Beaconing Pattern Detected",
                f"Regular HTTP communication from {src_ip} to {dest_ip} with interval ~{mean_interval:.1f}s (CoV={cov:.3f}).",
                event,
                mitre_tactic="TA0011",
                mitre_technique=["T1071.001"],
            )
        return None

    # -- Rule 8: DNS Tunneling ---------------------------------------------

    async def _check_dns_tunneling(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """DNS tunneling: long subdomains (>50 chars) with >10 queries in 60s."""
        query_name = self._get_flat(event, "dns.question.name")
        if query_name is None:
            return None

        # Check subdomain length
        subdomain = self._get_flat(event, "dns.question.subdomain") or ""
        if not subdomain:
            # Compute subdomain from query name
            parts = str(query_name).split(".")
            if len(parts) > 2:
                subdomain = ".".join(parts[:-2])

        if len(subdomain) < 50:
            return None

        src_ip = self._get_flat(event, "source.ip") or "unknown"
        key = f"cn:sw:dns_tunnel:{src_ip}"

        triggered = await self._tracker.increment_and_check(key, 60, 10)
        if triggered:
            return self._build_alert(
                "dns_tunneling", "CN-SW-DNS-001",
                "DNS Tunneling Suspected",
                f"Source {src_ip} sent 10+ DNS queries with long subdomains (>50 chars) within 60 seconds.",
                event,
                mitre_tactic="TA0010",
                mitre_technique=["T1048.003"],
            )
        return None

    # -- Rule 9: Impossible Travel -----------------------------------------

    async def _check_impossible_travel(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Impossible travel: same user, different country within 7200s."""
        outcome = self._get_flat(event, "event.outcome")
        if outcome != "success":
            return None
        categories = self._get_flat(event, "event.category") or []
        if isinstance(categories, str):
            categories = [categories]
        if "authentication" not in categories:
            return None

        user = self._get_flat(event, "user.name")
        country = self._get_flat(event, "source.geo.country_iso_code")
        if not user or not country:
            return None

        key = f"cn:sw:travel:{user}"
        now = time.time()

        # Get previous login locations
        pipe = self._redis.pipeline()
        pipe.zadd(key, {f"{country}:{now}": now})
        pipe.zremrangebyscore(key, "-inf", now - 7200)
        pipe.zrangebyscore(key, now - 7200, "+inf")
        pipe.expire(key, 14400)
        results = await pipe.execute()

        raw_members: list[bytes | str] = results[2]
        countries_seen: set[str] = set()
        for m in raw_members:
            decoded = m.decode("utf-8") if isinstance(m, bytes) else str(m)
            c = decoded.split(":")[0]
            countries_seen.add(c)

        if len(countries_seen) >= 2:
            return self._build_alert(
                "impossible_travel", "CN-SW-IT-001",
                "Impossible Travel Detected",
                f"User '{user}' authenticated from {len(countries_seen)} different countries "
                f"({', '.join(sorted(countries_seen))}) within 2 hours.",
                event,
                mitre_tactic="TA0001",
                mitre_technique=["T1078"],
            )
        return None

    # -- Rule 10: Privilege Escalation Chain --------------------------------

    async def _check_privilege_escalation_chain(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Privilege escalation chain: failed -> success -> admin_group in 600s."""
        user = self._get_flat(event, "user.name")
        if not user:
            return None

        # Determine event type for sequencing
        outcome = self._get_flat(event, "event.outcome")
        action = self._get_flat(event, "event.action") or ""
        categories = self._get_flat(event, "event.category") or []
        if isinstance(categories, str):
            categories = [categories]

        event_type: Optional[str] = None

        if "authentication" in categories and outcome == "failure":
            event_type = "failed"
        elif "authentication" in categories and outcome == "success":
            event_type = "success"
        elif action in ("added-member-to-group", "group-add") or "iam" in categories:
            group_name = (
                self._get_flat(event, "user.target.group.name")
                or self._get_flat(event, "user.group.name")
                or action
            )
            if group_name and any(
                kw in str(group_name).lower()
                for kw in ("admin", "domain admins", "root", "sudo", "wheel")
            ):
                event_type = "admin_group"

        if event_type is None:
            return None

        key = f"cn:sw:privesc:{user}"
        sequence = await self._tracker.track_sequence(key, event_type, 600)

        # Look for the chain: failed -> success -> admin_group
        has_failed = "failed" in sequence
        has_success = "success" in sequence
        has_admin = "admin_group" in sequence

        if has_failed and has_success and has_admin:
            # Verify order: at least one failed before success before admin_group
            first_failed = next((i for i, s in enumerate(sequence) if s == "failed"), -1)
            first_success = next((i for i, s in enumerate(sequence) if s == "success"), -1)
            first_admin = next((i for i, s in enumerate(sequence) if s == "admin_group"), -1)

            if 0 <= first_failed < first_success < first_admin:
                # Clear the sequence to avoid re-firing
                await self._redis.delete(key)
                return self._build_alert(
                    "privilege_escalation_chain", "CN-SW-PE-001",
                    "Privilege Escalation Chain Detected",
                    f"User '{user}' showed attack chain: failed login -> successful login -> "
                    f"added to admin group within 600 seconds.",
                    event,
                    mitre_tactic="TA0004",
                    mitre_technique=["T1078", "T1098"],
                )
        return None

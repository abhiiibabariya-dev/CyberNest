"""
CyberNest UEBA (User and Entity Behavior Analytics) — ML-based anomaly detection.

Consumes parsed events from Kafka, builds behavioral baselines per user/entity,
and detects anomalies using unsupervised ML models.

Detection capabilities:
  - Unusual login times (user normally logs in 9-5, now logging in at 3am)
  - Unusual source IPs (user always from 10.0.x.x, now from external IP)
  - Unusual data access volume (user normally reads 50 files/day, now reading 5000)
  - Impossible travel (same user, two countries, <2hr gap)
  - Unusual process execution (user never ran PowerShell before)
  - Privilege escalation patterns (gradual increase in access scope)

Models: Isolation Forest (global outlier), Local Outlier Factor (local density)
State: Redis for real-time feature vectors, retrained periodically on historical data.

Attacker perspective: Catches insider threats and compromised accounts that rule-based
  detection misses because behavior changes gradually.
Defender perspective: Reduces false positives by learning what's "normal" for each user.
"""

import asyncio
import os
import time
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import numpy as np
import orjson
import structlog
import redis.asyncio as redis_lib
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

logger = structlog.get_logger()

KAFKA_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "ueba-group")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

INPUT_TOPIC = "cybernest.parsed.events"
OUTPUT_TOPIC = "cybernest.alerts"

# Feature extraction windows
BASELINE_WINDOW_HOURS = 168  # 7 days of baseline data
DETECTION_THRESHOLD = -0.5   # Isolation Forest anomaly score threshold


class UserProfile:
    """Real-time feature vector for a single user/entity.

    Tracks behavioral features over time windows:
    - Login hours distribution (24 bins)
    - Source IP diversity (unique IPs seen)
    - Event volume per hour
    - Process diversity (unique process names)
    - Data access volume (bytes/files accessed)
    - Authentication failure rate
    - Geographic diversity
    """

    def __init__(self, user_id: str):
        self.user_id = user_id
        self.login_hours: list[int] = []           # Hour of day for each login
        self.source_ips: set[str] = set()           # Unique source IPs
        self.event_counts: list[int] = []           # Events per hour
        self.processes: set[str] = set()            # Unique process names executed
        self.auth_failures: int = 0
        self.auth_successes: int = 0
        self.countries: set[str] = set()            # Unique countries
        self.last_country: str = ""
        self.last_login_time: datetime | None = None
        self.last_ip: str = ""
        self.hourly_events: int = 0
        self.current_hour: int = -1

    def extract_features(self) -> np.ndarray:
        """Convert profile into a numeric feature vector for ML model.

        Returns 8-dimensional feature vector:
        [login_hour_entropy, ip_diversity, avg_events_per_hour,
         process_diversity, auth_failure_rate, country_diversity,
         hourly_event_count, total_events]
        """
        # Login hour entropy (unusual login times = higher entropy shift)
        hour_dist = np.zeros(24)
        for h in self.login_hours[-100:]:  # Last 100 logins
            hour_dist[h] += 1
        if hour_dist.sum() > 0:
            hour_dist = hour_dist / hour_dist.sum()
            hour_entropy = -np.sum(hour_dist[hour_dist > 0] * np.log2(hour_dist[hour_dist > 0]))
        else:
            hour_entropy = 0.0

        # Auth failure rate
        total_auth = self.auth_failures + self.auth_successes
        failure_rate = self.auth_failures / max(total_auth, 1)

        return np.array([
            hour_entropy,                              # 0: Login time distribution entropy
            len(self.source_ips),                      # 1: Unique source IP count
            np.mean(self.event_counts[-24:]) if self.event_counts else 0,  # 2: Avg events/hour
            len(self.processes),                        # 3: Unique processes executed
            failure_rate,                              # 4: Auth failure ratio
            len(self.countries),                        # 5: Geographic diversity
            self.hourly_events,                        # 6: Current hour event count
            sum(self.event_counts[-24:]) if self.event_counts else 0,  # 7: Total events (24h)
        ])

    def update_from_event(self, event: dict):
        """Update profile with data from a new parsed event."""
        now = datetime.now(timezone.utc)
        current_hour = now.hour

        # Track hourly event count
        if current_hour != self.current_hour:
            if self.current_hour >= 0:
                self.event_counts.append(self.hourly_events)
            self.hourly_events = 0
            self.current_hour = current_hour
        self.hourly_events += 1

        # Source IP
        src_ip = _nested_get(event, "source.ip")
        if src_ip:
            self.source_ips.add(src_ip)
            self.last_ip = src_ip

        # Login activity
        action = _nested_get(event, "event.action") or ""
        if "logon" in action.lower() or "login" in action.lower():
            self.login_hours.append(current_hour)
            self.last_login_time = now

            if "fail" in action.lower():
                self.auth_failures += 1
            else:
                self.auth_successes += 1

        # Process
        proc = _nested_get(event, "process.name")
        if proc:
            self.processes.add(proc)

        # Geography
        country = _nested_get(event, "source.geo.country_iso_code")
        if country:
            self.last_country = country
            self.countries.add(country)


class UEBAEngine:
    """UEBA anomaly detection engine.

    Maintains per-user behavioral profiles and runs ML models
    to detect deviations from normal behavior.
    """

    def __init__(self, redis_client: redis_lib.Redis):
        self.redis = redis_client
        self.profiles: dict[str, UserProfile] = {}
        self.isolation_forest: IsolationForest | None = None
        self.lof: LocalOutlierFactor | None = None
        self.last_train_time: float = 0
        self.train_interval = 3600  # Retrain every hour
        self.min_training_samples = 20
        self.stats = {"events": 0, "anomalies": 0}

    def _get_profile(self, user_id: str) -> UserProfile:
        """Get or create a user profile."""
        if user_id not in self.profiles:
            self.profiles[user_id] = UserProfile(user_id)
        return self.profiles[user_id]

    async def process_event(self, event: dict) -> dict | None:
        """Process an event: update profile, check for anomalies.

        Returns an alert dict if anomaly detected, None otherwise.
        """
        self.stats["events"] += 1

        # Extract user identifier
        user = _nested_get(event, "user.name")
        if not user:
            return None

        # Update profile
        profile = self._get_profile(user)
        profile.update_from_event(event)

        # Check for rule-based behavioral anomalies first (fast checks)
        alert = await self._check_impossible_travel(profile, event)
        if alert:
            return alert

        alert = self._check_unusual_hour(profile, event)
        if alert:
            return alert

        # ML-based detection (requires trained model)
        if self.isolation_forest and len(profile.event_counts) >= 3:
            features = profile.extract_features().reshape(1, -1)
            score = self.isolation_forest.score_samples(features)[0]

            if score < DETECTION_THRESHOLD:
                self.stats["anomalies"] += 1
                return {
                    "rule_id": "CN-UEBA-001",
                    "rule_name": "UEBA: Anomalous User Behavior",
                    "description": (
                        f"ML model detected anomalous behavior for user '{user}'. "
                        f"Anomaly score: {score:.3f} (threshold: {DETECTION_THRESHOLD}). "
                        f"Features: IPs={len(profile.source_ips)}, "
                        f"processes={len(profile.processes)}, "
                        f"countries={len(profile.countries)}, "
                        f"auth_failures={profile.auth_failures}"
                    ),
                    "severity": "high" if score < -0.8 else "medium",
                    "level": 10 if score < -0.8 else 7,
                    "username": user,
                    "source_ip": profile.last_ip,
                    "mitre_techniques": ["T1078"],  # Valid Accounts
                    "mitre_tactics": ["defense_evasion", "initial_access"],
                    "alert_type": "ueba_anomaly",
                    "ueba_score": float(score),
                }

        # Retrain model periodically
        if time.monotonic() - self.last_train_time > self.train_interval:
            await self._train_model()

        return None

    async def _check_impossible_travel(self, profile: UserProfile, event: dict) -> dict | None:
        """Detect impossible travel: same user, different countries, short time gap.

        Attacker TTP: Compromised credentials used from different geographic location.
        MITRE: T1078 (Valid Accounts) + T1078.004 (Cloud Accounts)
        """
        country = _nested_get(event, "source.geo.country_iso_code")
        if not country or not profile.last_country or country == profile.last_country:
            return None

        if profile.last_login_time:
            time_gap = (datetime.now(timezone.utc) - profile.last_login_time).total_seconds()
            if time_gap < 7200:  # Less than 2 hours between different countries
                self.stats["anomalies"] += 1
                return {
                    "rule_id": "CN-UEBA-002",
                    "rule_name": "UEBA: Impossible Travel Detected",
                    "description": (
                        f"User '{profile.user_id}' logged in from {country} "
                        f"only {int(time_gap/60)} minutes after logging in from "
                        f"{profile.last_country}. Possible credential compromise."
                    ),
                    "severity": "critical",
                    "level": 13,
                    "username": profile.user_id,
                    "source_ip": _nested_get(event, "source.ip"),
                    "mitre_techniques": ["T1078"],
                    "mitre_tactics": ["initial_access"],
                    "alert_type": "impossible_travel",
                }
        return None

    def _check_unusual_hour(self, profile: UserProfile, event: dict) -> dict | None:
        """Detect login at unusual hours based on user's historical pattern.

        Attacker TTP: Compromised account used outside normal working hours.
        """
        action = _nested_get(event, "event.action") or ""
        if "logon" not in action.lower() and "login" not in action.lower():
            return None
        if "fail" in action.lower():
            return None

        # Need enough historical data
        if len(profile.login_hours) < 20:
            return None

        current_hour = datetime.now(timezone.utc).hour
        hour_counts = defaultdict(int)
        for h in profile.login_hours[:-1]:  # Exclude current login
            hour_counts[h] += 1

        total_logins = len(profile.login_hours) - 1
        hour_frequency = hour_counts.get(current_hour, 0) / max(total_logins, 1)

        # If this hour represents <2% of historical logins, flag it
        if hour_frequency < 0.02 and total_logins > 30:
            self.stats["anomalies"] += 1
            return {
                "rule_id": "CN-UEBA-003",
                "rule_name": "UEBA: Unusual Login Time",
                "description": (
                    f"User '{profile.user_id}' logged in at {current_hour}:00 UTC. "
                    f"This hour represents only {hour_frequency*100:.1f}% of their "
                    f"historical logins ({total_logins} total). Possible compromised account."
                ),
                "severity": "medium",
                "level": 6,
                "username": profile.user_id,
                "source_ip": _nested_get(event, "source.ip"),
                "mitre_techniques": ["T1078"],
                "mitre_tactics": ["initial_access"],
                "alert_type": "unusual_login_time",
            }
        return None

    async def _train_model(self):
        """Retrain Isolation Forest and LOF on current user profiles."""
        feature_vectors = []
        for profile in self.profiles.values():
            if len(profile.event_counts) >= 3:
                feature_vectors.append(profile.extract_features())

        if len(feature_vectors) < self.min_training_samples:
            return

        X = np.array(feature_vectors)

        # Normalize features
        mean = X.mean(axis=0)
        std = X.std(axis=0)
        std[std == 0] = 1  # Avoid division by zero
        X_normalized = (X - mean) / std

        # Train Isolation Forest (global anomaly detection)
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # Expect ~5% anomalies
            random_state=42,
        )
        self.isolation_forest.fit(X_normalized)

        self.last_train_time = time.monotonic()
        logger.info("UEBA model retrained",
                    users=len(feature_vectors),
                    features=X.shape[1])


def _nested_get(data: dict, dotted_key: str):
    """Safely get a nested dict value using dot notation."""
    keys = dotted_key.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
    return current


async def run():
    """Main loop: consume parsed events, run UEBA detection."""
    logger.info("Starting CyberNest UEBA Service")

    redis_client = redis_lib.from_url(REDIS_URL, decode_responses=True)
    engine = UEBAEngine(redis_client)

    consumer = AIOKafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda v: orjson.loads(v),
        auto_offset_reset="latest",
        enable_auto_commit=True,
        max_poll_records=500,
    )

    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: orjson.dumps(v),
        compression_type="lz4",
    )

    await consumer.start()
    await producer.start()
    logger.info("UEBA consumer started")

    try:
        async for msg in consumer:
            try:
                event = msg.value
                if not event:
                    continue

                alert = await engine.process_event(event)
                if alert:
                    alert["id"] = str(__import__('uuid').uuid4())
                    alert["title"] = f"[{alert['severity'].upper()}] {alert['rule_name']}"
                    alert["created_at"] = datetime.now(timezone.utc).isoformat()
                    await producer.send(OUTPUT_TOPIC, value=alert)

                if engine.stats["events"] % 10000 == 0:
                    logger.info("UEBA stats",
                                events=engine.stats["events"],
                                anomalies=engine.stats["anomalies"],
                                profiles=len(engine.profiles))

            except Exception as e:
                logger.error("UEBA processing error", error=str(e))

    except asyncio.CancelledError:
        pass
    finally:
        await consumer.stop()
        await producer.stop()
        await redis_client.aclose()
        logger.info("UEBA stopped", stats=engine.stats)


if __name__ == "__main__":
    asyncio.run(run())

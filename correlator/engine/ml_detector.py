"""
CyberNest UEBA ML Anomaly Detector.

Uses IsolationForest for per-user behavioral anomaly detection.

Features per user:
  - login_hour (0-23)
  - login_day_of_week (0-6)
  - source_ip (label-encoded)
  - country_code (label-encoded)
  - data_transferred_bytes

Training:
  - Uses last 7 days of user activity from PostgreSQL
  - Retrains every 24 hours per user
  - Only activates after user has >100 events

Scoring:
  - Anomaly score 0.0 to 1.0
  - Alert threshold: >0.85

Storage:
  - Trained models stored as pickle in Redis (TTL: 25 hours)
  - Baselines stored in PostgreSQL
"""

from __future__ import annotations

import hashlib
import io
import pickle
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import numpy as np

from shared.utils.logger import get_logger

logger = get_logger("correlator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_EVENTS_FOR_MODEL = 100
RETRAIN_INTERVAL_SECONDS = 86400  # 24 hours
MODEL_TTL_SECONDS = 90000  # 25 hours
ANOMALY_THRESHOLD = 0.85
TRAINING_WINDOW_DAYS = 7

# Feature names in order
FEATURE_NAMES = [
    "login_hour",
    "login_day_of_week",
    "source_ip_encoded",
    "country_code_encoded",
    "data_transferred_bytes",
]


# ---------------------------------------------------------------------------
# Label encoder (deterministic hash-based)
# ---------------------------------------------------------------------------

def _encode_categorical(value: Optional[str], max_val: int = 1000) -> int:
    """Encode a categorical string to an integer using deterministic hashing."""
    if value is None or value == "":
        return 0
    h = hashlib.md5(str(value).encode(), usedforsecurity=False).hexdigest()
    return int(h, 16) % max_val


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(event: dict[str, Any]) -> Optional[np.ndarray]:
    """Extract ML features from an ECS event dict.

    Returns a 1D numpy array of shape (5,) or None if the event is not
    suitable for UEBA analysis (e.g., missing user).
    """
    user = _get_nested(event, "user.name")
    if not user:
        return None

    # Timestamp
    ts_raw = _get_nested(event, "@timestamp") or _get_nested(event, "timestamp")
    if isinstance(ts_raw, str):
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)
    elif isinstance(ts_raw, datetime):
        ts = ts_raw
    else:
        ts = datetime.now(timezone.utc)

    login_hour = ts.hour
    login_dow = ts.weekday()  # 0=Monday, 6=Sunday

    src_ip = _get_nested(event, "source.ip")
    country = _get_nested(event, "source.geo.country_iso_code")

    data_bytes = (
        _get_nested(event, "source.bytes")
        or _get_nested(event, "network.bytes")
        or 0
    )
    try:
        data_bytes = int(data_bytes)
    except (ValueError, TypeError):
        data_bytes = 0

    features = np.array([
        float(login_hour),
        float(login_dow),
        float(_encode_categorical(src_ip)),
        float(_encode_categorical(country)),
        float(data_bytes),
    ], dtype=np.float64)

    return features


def _get_nested(d: dict[str, Any], dotted_key: str) -> Any:
    """Resolve a dotted key from a nested dict."""
    parts = dotted_key.split(".")
    current: Any = d
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


# ---------------------------------------------------------------------------
# ML Detector
# ---------------------------------------------------------------------------

class MLDetector:
    """UEBA anomaly detector using IsolationForest.

    Models are stored per-user in Redis as pickled objects.
    Training data (baselines) is stored in PostgreSQL.
    """

    def __init__(self, redis_client: Any, pg_pool: Any = None) -> None:
        self._redis = redis_client
        self._pg_pool = pg_pool
        self._last_train_check: dict[str, float] = {}

    # -- Scoring -----------------------------------------------------------

    async def score(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Score an event for anomalous behavior.

        Returns an alert dict if anomaly score exceeds the threshold,
        or None if normal / insufficient data.
        """
        user = _get_nested(event, "user.name")
        if not user:
            return None

        features = extract_features(event)
        if features is None:
            return None

        # Store the feature vector for future training
        await self._store_feature(user, features)

        # Check if model exists
        model = await self._load_model(user)
        if model is None:
            # Check if we should train
            await self._maybe_train(user)
            return None

        # Score the event
        try:
            # IsolationForest decision_function: negative = anomaly
            score_raw = model.decision_function(features.reshape(1, -1))[0]
            # Convert to 0-1 scale where 1 = most anomalous
            # IsolationForest scores: negative = anomaly, positive = normal
            # Typical range: -0.5 to 0.5
            anomaly_score = max(0.0, min(1.0, 0.5 - score_raw))
        except Exception:
            logger.exception("ml scoring failed", user=user)
            return None

        if anomaly_score > ANOMALY_THRESHOLD:
            return self._build_alert(user, anomaly_score, features, event)

        return None

    # -- Training ----------------------------------------------------------

    async def _maybe_train(self, user: str) -> None:
        """Check if a user's model needs (re)training."""
        now = time.time()
        last_check = self._last_train_check.get(user, 0)
        if now - last_check < 300:  # Only check every 5 minutes
            return

        self._last_train_check[user] = now

        # Check event count
        event_count = await self._get_event_count(user)
        if event_count < MIN_EVENTS_FOR_MODEL:
            return

        # Check if model exists and is recent
        model_age = await self._get_model_age(user)
        if model_age is not None and model_age < RETRAIN_INTERVAL_SECONDS:
            return

        # Train the model
        await self.train_user_model(user)

    async def train_user_model(self, user: str) -> bool:
        """Train an IsolationForest model for a specific user.

        Returns True if training succeeded.
        """
        try:
            features_matrix = await self._load_training_data(user)
            if features_matrix is None or len(features_matrix) < MIN_EVENTS_FOR_MODEL:
                logger.debug(
                    "insufficient training data",
                    user=user,
                    count=0 if features_matrix is None else len(features_matrix),
                )
                return False

            # Lazy import to avoid startup overhead
            from sklearn.ensemble import IsolationForest

            model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                max_samples="auto",
                random_state=42,
                n_jobs=1,
            )
            model.fit(features_matrix)

            # Store model in Redis
            await self._save_model(user, model)

            logger.info(
                "ml model trained",
                user=user,
                training_samples=len(features_matrix),
            )
            return True

        except Exception:
            logger.exception("ml training failed", user=user)
            return False

    # -- Redis model storage -----------------------------------------------

    async def _save_model(self, user: str, model: Any) -> None:
        """Pickle and store model in Redis."""
        key = f"cn:ml:model:{user}"
        ts_key = f"cn:ml:model_ts:{user}"

        buf = io.BytesIO()
        pickle.dump(model, buf)
        model_bytes = buf.getvalue()

        pipe = self._redis.pipeline()
        pipe.set(key, model_bytes, ex=MODEL_TTL_SECONDS)
        pipe.set(ts_key, str(time.time()), ex=MODEL_TTL_SECONDS)
        await pipe.execute()

    async def _load_model(self, user: str) -> Any:
        """Load a pickled model from Redis."""
        key = f"cn:ml:model:{user}"
        model_bytes = await self._redis.get(key)
        if model_bytes is None:
            return None

        try:
            buf = io.BytesIO(model_bytes)
            model = pickle.loads(buf.read())
            return model
        except Exception:
            logger.exception("failed to unpickle model", user=user)
            return None

    async def _get_model_age(self, user: str) -> Optional[float]:
        """Get the age of the stored model in seconds."""
        ts_key = f"cn:ml:model_ts:{user}"
        ts_raw = await self._redis.get(ts_key)
        if ts_raw is None:
            return None
        try:
            model_ts = float(ts_raw)
            return time.time() - model_ts
        except (ValueError, TypeError):
            return None

    # -- Feature storage (Redis-backed for speed) ---------------------------

    async def _store_feature(self, user: str, features: np.ndarray) -> None:
        """Store a feature vector in Redis for future training."""
        key = f"cn:ml:features:{user}"
        now = time.time()
        member = features.tobytes().hex() + f":{now}"

        pipe = self._redis.pipeline()
        pipe.zadd(key, {member: now})
        # Keep 7 days of data
        pipe.zremrangebyscore(key, "-inf", now - (TRAINING_WINDOW_DAYS * 86400))
        pipe.expire(key, TRAINING_WINDOW_DAYS * 86400 + 3600)
        await pipe.execute()

    async def _load_training_data(self, user: str) -> Optional[np.ndarray]:
        """Load stored feature vectors for training."""
        key = f"cn:ml:features:{user}"
        now = time.time()
        cutoff = now - (TRAINING_WINDOW_DAYS * 86400)

        raw_members = await self._redis.zrangebyscore(key, cutoff, "+inf")
        if not raw_members:
            return None

        feature_list: list[np.ndarray] = []
        for m in raw_members:
            decoded = m.decode("utf-8") if isinstance(m, bytes) else str(m)
            hex_part = decoded.rsplit(":", 1)[0]
            try:
                feature_bytes = bytes.fromhex(hex_part)
                features = np.frombuffer(feature_bytes, dtype=np.float64)
                if len(features) == len(FEATURE_NAMES):
                    feature_list.append(features)
            except (ValueError, IndexError):
                continue

        if not feature_list:
            return None

        return np.vstack(feature_list)

    async def _get_event_count(self, user: str) -> int:
        """Get the number of stored feature vectors for a user."""
        key = f"cn:ml:features:{user}"
        count = await self._redis.zcard(key)
        return int(count) if count else 0

    # -- PostgreSQL baseline storage (optional) ----------------------------

    async def store_baseline(self, user: str, baseline: dict[str, Any]) -> None:
        """Store a user behavior baseline in PostgreSQL."""
        if self._pg_pool is None:
            return

        try:
            import json
            async with self._pg_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO ueba_baselines (username, baseline_data, updated_at)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (username) DO UPDATE
                    SET baseline_data = $2, updated_at = $3
                    """,
                    user,
                    json.dumps(baseline),
                    datetime.now(timezone.utc),
                )
        except Exception:
            logger.exception("failed to store baseline", user=user)

    async def load_baseline(self, user: str) -> Optional[dict[str, Any]]:
        """Load a user behavior baseline from PostgreSQL."""
        if self._pg_pool is None:
            return None

        try:
            import json
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT baseline_data FROM ueba_baselines WHERE username = $1",
                    user,
                )
                if row:
                    return json.loads(row["baseline_data"])
        except Exception:
            logger.exception("failed to load baseline", user=user)

        return None

    async def init_pg_schema(self) -> None:
        """Create the PostgreSQL table for UEBA baselines if it doesn't exist."""
        if self._pg_pool is None:
            return

        try:
            async with self._pg_pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS ueba_baselines (
                        username VARCHAR(255) PRIMARY KEY,
                        baseline_data JSONB NOT NULL DEFAULT '{}',
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
                await conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ueba_baselines_updated
                    ON ueba_baselines (updated_at)
                """)
            logger.info("ueba_baselines table initialized")
        except Exception:
            logger.exception("failed to init ueba schema")

    # -- Alert building ----------------------------------------------------

    def _build_alert(
        self,
        user: str,
        score: float,
        features: np.ndarray,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        from uuid import uuid4
        now = datetime.now(timezone.utc).isoformat()

        feature_detail = {}
        for i, name in enumerate(FEATURE_NAMES):
            feature_detail[name] = float(features[i])

        severity = "high" if score > 0.95 else "medium" if score > 0.9 else "high"

        return {
            "alert_id": uuid4().hex,
            "rule_id": "CN-ML-UEBA-001",
            "rule_name": "UEBA Anomaly Detection",
            "severity": severity,
            "status": "new",
            "title": f"[CN-ML-UEBA-001] Anomalous User Behavior: {user}",
            "description": (
                f"User '{user}' exhibited anomalous behavior with an anomaly "
                f"score of {score:.3f} (threshold: {ANOMALY_THRESHOLD}). "
                f"Features: {feature_detail}"
            ),
            "source_ip": _get_nested(event, "source.ip"),
            "destination_ip": _get_nested(event, "destination.ip"),
            "username": user,
            "hostname": _get_nested(event, "host.hostname") or _get_nested(event, "host.name"),
            "raw_log": _get_nested(event, "raw") or _get_nested(event, "message"),
            "parsed_event": event,
            "event_ids": [_get_nested(event, "cybernest.event_id") or uuid4().hex],
            "event_count": 1,
            "mitre_tactic": "TA0001",
            "mitre_technique": ["T1078"],
            "risk_score": min(100.0, score * 100),
            "category": "ueba_anomaly",
            "ml_score": score,
            "ml_features": feature_detail,
            "created_at": now,
            "updated_at": now,
        }

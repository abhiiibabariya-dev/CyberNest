#!/usr/bin/env python3
"""
CyberNest SIEM + SOAR Platform - Database Seed Script
======================================================
Reads detection rules from correlator/rules/ and playbooks from
config/playbooks/, then inserts them into PostgreSQL along with
default users and sample notification channels.

Usage:
    python scripts/seed-rules.py

Environment variables (or defaults from docker-compose):
    POSTGRES_HOST     (default: localhost)
    POSTGRES_PORT     (default: 5432)
    POSTGRES_DB       (default: cybernest)
    POSTGRES_USER     (default: cybernest)
    POSTGRES_PASSWORD (default: CyberNest2025!)
"""

import hashlib
import os
import sys
import glob
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[WARN] PyYAML not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("[WARN] psycopg2 not installed. Installing psycopg2-binary...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary", "-q"])
    import psycopg2
    import psycopg2.extras

try:
    import bcrypt
except ImportError:
    print("[WARN] bcrypt not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "bcrypt", "-q"])
    import bcrypt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
RULES_DIR = PROJECT_DIR / "correlator" / "rules"
PLAYBOOKS_DIR = PROJECT_DIR / "config" / "playbooks"

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "dbname": os.getenv("POSTGRES_DB", "cybernest"),
    "user": os.getenv("POSTGRES_USER", "cybernest"),
    "password": os.getenv("POSTGRES_PASSWORD", "CyberNest2025!"),
}

# Severity string -> integer mapping for the rules.level column (1-5)
LEVEL_MAP = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

# ---------------------------------------------------------------------------
# Default users
# ---------------------------------------------------------------------------

DEFAULT_USERS = [
    {
        "username": "admin",
        "email": "admin@cybernest.local",
        "password": "CyberNest@2025!",
        "role": "super_admin",
    },
    {
        "username": "analyst",
        "email": "analyst@cybernest.local",
        "password": "Analyst@2025!",
        "role": "analyst",
    },
]

# ---------------------------------------------------------------------------
# Default notification channels
# ---------------------------------------------------------------------------

DEFAULT_CHANNELS = [
    {
        "name": "SOC Email",
        "channel_type": "email",
        "config_json": {
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "smtp_user": "alerts@cybernest.local",
            "smtp_password": "",
            "recipients": ["soc-team@cybernest.local"],
            "use_tls": True,
        },
        "is_enabled": False,
    },
    {
        "name": "Slack SOC Channel",
        "channel_type": "slack",
        "config_json": {
            "webhook_url": "https://hooks.slack.com/services/REPLACE/WITH/WEBHOOK",
            "channel": "#soc-alerts",
            "username": "CyberNest",
            "icon_emoji": ":shield:",
        },
        "is_enabled": False,
    },
    {
        "name": "PagerDuty On-Call",
        "channel_type": "pagerduty",
        "config_json": {
            "routing_key": "REPLACE_WITH_PAGERDUTY_ROUTING_KEY",
            "severity_mapping": {
                "critical": "critical",
                "high": "error",
                "medium": "warning",
                "low": "info",
            },
        },
        "is_enabled": False,
    },
    {
        "name": "Microsoft Teams",
        "channel_type": "teams",
        "config_json": {
            "webhook_url": "https://outlook.office.com/webhook/REPLACE/WITH/URL",
        },
        "is_enabled": False,
    },
    {
        "name": "SIEM Webhook",
        "channel_type": "webhook",
        "config_json": {
            "url": "https://siem-webhook.example.com/cybernest",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "X-Source": "CyberNest"},
            "timeout": 10,
        },
        "is_enabled": False,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Generate bcrypt hash compatible with the existing init.sql format."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def collect_yaml_files(directory: Path) -> list[Path]:
    """Recursively find all .yml and .yaml files in directory."""
    files = []
    if not directory.exists():
        return files
    for ext in ("*.yml", "*.yaml"):
        files.extend(directory.rglob(ext))
    return sorted(files)


def parse_rules_file(filepath: Path) -> list[dict]:
    """Parse a YAML rules file and return a list of rule dicts."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data is None:
        return []
    # Handle both top-level list and {"rules": [...]} format
    if isinstance(data, dict) and "rules" in data:
        return data["rules"] if isinstance(data["rules"], list) else []
    if isinstance(data, list):
        return data
    return []


def parse_playbook_file(filepath: Path) -> dict | None:
    """Parse a single playbook YAML file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data and isinstance(data, dict) and "name" in data:
        return data
    return None


# ---------------------------------------------------------------------------
# Seed functions
# ---------------------------------------------------------------------------


def seed_users(cur) -> int:
    """Insert default users if they don't already exist."""
    inserted = 0
    for user in DEFAULT_USERS:
        cur.execute("SELECT 1 FROM users WHERE username = %s", (user["username"],))
        if cur.fetchone():
            print(f"  [SKIP] User '{user['username']}' already exists")
            continue
        pw_hash = hash_password(user["password"])
        cur.execute(
            """
            INSERT INTO users (username, email, password_hash, role, is_active)
            VALUES (%s, %s, %s, %s, TRUE)
            """,
            (user["username"], user["email"], pw_hash, user["role"]),
        )
        inserted += 1
        print(f"  [ADD]  User '{user['username']}' ({user['role']})")
    return inserted


def seed_rules(cur) -> int:
    """Read all rule YAML files and insert into the rules table."""
    rule_files = collect_yaml_files(RULES_DIR)
    if not rule_files:
        print("  [WARN] No rule files found in", RULES_DIR)
        return 0

    inserted = 0
    skipped = 0
    for filepath in rule_files:
        rules = parse_rules_file(filepath)
        rel_path = filepath.relative_to(PROJECT_DIR)
        for rule in rules:
            rule_id = rule.get("id", "")
            if not rule_id:
                continue

            # Check if already exists
            cur.execute("SELECT 1 FROM rules WHERE rule_id = %s", (rule_id,))
            if cur.fetchone():
                skipped += 1
                continue

            name = rule.get("name", rule_id)
            description = rule.get("description", "")
            level_str = rule.get("level", "medium")
            level_int = LEVEL_MAP.get(level_str.lower(), 3)
            category = rule.get("category", "")
            mitre_tactic = rule.get("mitre_tactic", "")
            mitre_technique = rule.get("mitre_technique", [])
            if isinstance(mitre_technique, str):
                mitre_technique = [mitre_technique]
            is_enabled = rule.get("enabled", True)

            # Store full YAML of the individual rule
            content_yaml = yaml.dump(rule, default_flow_style=False, sort_keys=False)

            cur.execute(
                """
                INSERT INTO rules (rule_id, name, description, level, category,
                                   mitre_tactic, mitre_technique, content_yaml, is_enabled)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    rule_id,
                    name,
                    description,
                    level_int,
                    category,
                    mitre_tactic,
                    mitre_technique,
                    content_yaml,
                    is_enabled,
                ),
            )
            inserted += 1

    print(f"  [ADD]  {inserted} rules inserted, {skipped} already existed")
    print(f"  [INFO] Scanned {len(rule_files)} rule files from {RULES_DIR.relative_to(PROJECT_DIR)}")
    return inserted


def seed_playbooks(cur) -> int:
    """Read all playbook YAML files and insert into the playbooks table."""
    pb_files = collect_yaml_files(PLAYBOOKS_DIR)
    if not pb_files:
        print("  [WARN] No playbook files found in", PLAYBOOKS_DIR)
        return 0

    inserted = 0
    skipped = 0
    for filepath in pb_files:
        playbook = parse_playbook_file(filepath)
        if not playbook:
            continue

        name = playbook.get("name", filepath.stem)

        # Check if already exists
        cur.execute("SELECT 1 FROM playbooks WHERE name = %s", (name,))
        if cur.fetchone():
            skipped += 1
            continue

        description = playbook.get("description", "")
        trigger = playbook.get("trigger", {})
        trigger_type = "alert" if trigger else "manual"
        trigger_conditions = psycopg2.extras.Json(trigger) if trigger else psycopg2.extras.Json({})
        is_enabled = playbook.get("enabled", True)

        content_yaml = yaml.dump(playbook, default_flow_style=False, sort_keys=False)

        cur.execute(
            """
            INSERT INTO playbooks (name, description, trigger_type, trigger_conditions,
                                   content_yaml, is_enabled)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (name, description, trigger_type, trigger_conditions, content_yaml, is_enabled),
        )
        inserted += 1

    print(f"  [ADD]  {inserted} playbooks inserted, {skipped} already existed")
    print(f"  [INFO] Scanned {len(pb_files)} playbook files from {PLAYBOOKS_DIR.relative_to(PROJECT_DIR)}")
    return inserted


def seed_notification_channels(cur) -> int:
    """Insert default notification channels."""
    inserted = 0
    for ch in DEFAULT_CHANNELS:
        cur.execute(
            "SELECT 1 FROM notification_channels WHERE name = %s AND channel_type = %s",
            (ch["name"], ch["channel_type"]),
        )
        if cur.fetchone():
            print(f"  [SKIP] Channel '{ch['name']}' already exists")
            continue

        cur.execute(
            """
            INSERT INTO notification_channels (name, channel_type, config_json, is_enabled)
            VALUES (%s, %s, %s, %s)
            """,
            (
                ch["name"],
                ch["channel_type"],
                psycopg2.extras.Json(ch["config_json"]),
                ch["is_enabled"],
            ),
        )
        inserted += 1
        print(f"  [ADD]  Channel '{ch['name']}' ({ch['channel_type']})")
    return inserted


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("=" * 60)
    print("  CyberNest Database Seed Script")
    print("=" * 60)
    print()
    print(f"  Database: {DB_CONFIG['user']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}")
    print(f"  Rules:    {RULES_DIR}")
    print(f"  Playbooks:{PLAYBOOKS_DIR}")
    print()

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = False
        cur = conn.cursor()
    except psycopg2.OperationalError as e:
        print(f"[ERROR] Cannot connect to PostgreSQL: {e}")
        print("        Make sure PostgreSQL is running and accessible.")
        sys.exit(1)

    try:
        # Seed users
        print("[1/4] Seeding users...")
        user_count = seed_users(cur)

        # Seed rules
        print("\n[2/4] Seeding detection rules...")
        rule_count = seed_rules(cur)

        # Seed playbooks
        print("\n[3/4] Seeding SOAR playbooks...")
        pb_count = seed_playbooks(cur)

        # Seed notification channels
        print("\n[4/4] Seeding notification channels...")
        ch_count = seed_notification_channels(cur)

        conn.commit()

        # Summary
        print()
        print("=" * 60)
        print("  Seed Summary")
        print("=" * 60)
        print(f"  Users:                 {user_count} inserted")
        print(f"  Detection Rules:       {rule_count} inserted")
        print(f"  SOAR Playbooks:        {pb_count} inserted")
        print(f"  Notification Channels: {ch_count} inserted")
        print("=" * 60)
        print()
        print("[OK] Database seeded successfully.")

    except Exception as e:
        conn.rollback()
        print(f"\n[ERROR] Seed failed: {e}")
        sys.exit(1)
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()

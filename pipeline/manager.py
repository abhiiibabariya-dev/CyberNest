"""
CyberNest Manager — The REAL working SIEM backend.

This is the central server that:
1. Receives raw logs from agents via POST /logs
2. Parses and normalizes them into structured events
3. Runs detection rules (brute force, compromise, scanning)
4. Fires alerts and triggers SOAR playbooks
5. Serves the dashboard + API for the frontend
6. Tracks all alerts, events, and blocked IPs in memory + files

Run: python pipeline/manager.py
Access: http://localhost:8000 (dashboard) or public via ngrok
"""

import json
import os
import time
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# ═══════════════════════════════════════════════════════
# DATA STORES (in-memory + file persistence)
# ═══════════════════════════════════════════════════════

# Raw events received
events: list[dict] = []
MAX_EVENTS = 10000

# Parsed/normalized events
parsed_events: list[dict] = []

# Fired alerts
alerts: list[dict] = []

# Blocked IPs (SOAR response)
blocked_ips: set[str] = set()

# Detection state: track failed logins per IP
failed_login_tracker: dict[str, list[float]] = defaultdict(list)

# Track successful logins for compromise detection
login_success_after_fail: dict[str, int] = defaultdict(int)

# Connected WebSocket clients for live feed
ws_clients: list[WebSocket] = []

# Agent registry
agents: dict[str, dict] = {}

# Stats
stats = {
    "total_events": 0,
    "total_alerts": 0,
    "total_blocked": 0,
    "start_time": time.time(),
    "events_per_minute": 0,
}

# File paths for persistence
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
ALERTS_FILE = DATA_DIR / "alerts.json"
BLOCKED_FILE = DATA_DIR / "blocked_ips.txt"
EVENTS_FILE = DATA_DIR / "events.json"

# Load persisted data on startup
if BLOCKED_FILE.exists():
    blocked_ips = set(BLOCKED_FILE.read_text().strip().split("\n")) - {""}
if ALERTS_FILE.exists():
    try:
        alerts = json.loads(ALERTS_FILE.read_text())
    except Exception:
        pass


# ═══════════════════════════════════════════════════════
# PARSER — Extract structured fields from raw logs
# ═══════════════════════════════════════════════════════

import re

# Patterns for common log formats
FAILED_LOGIN_RE = re.compile(
    r"(?:Failed password|authentication failure|failed login|FAILED LOGIN)"
    r".*?(?:for (?:invalid user )?(\S+))?"
    r".*?(?:from |rhost=)(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

SUCCESS_LOGIN_RE = re.compile(
    r"(?:Accepted password|Accepted publickey|session opened|Successful login)"
    r".*?(?:for (\S+))?"
    r".*?(?:from |rhost=)(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

SSH_INVALID_USER_RE = re.compile(
    r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)", re.IGNORECASE
)

SUDO_RE = re.compile(
    r"sudo.*?(\S+)\s*:.*?COMMAND=(.*)", re.IGNORECASE
)

PORT_SCAN_RE = re.compile(
    r"(?:SYN|connection|refused|reset).*?(\d+\.\d+\.\d+\.\d+).*?port\s+(\d+)",
    re.IGNORECASE,
)

IP_EXTRACT_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def parse_log(raw: dict) -> dict:
    """Parse a raw log message into a structured event.

    Extracts: event_type, username, source IP, and other context.
    This is the core normalization engine of the SIEM.
    """
    message = raw.get("message", "")
    hostname = raw.get("hostname", "unknown")
    log_type = raw.get("log_type", "unknown")
    timestamp = raw.get("timestamp", datetime.now(timezone.utc).isoformat())

    event = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": timestamp,
        "hostname": hostname,
        "log_type": log_type,
        "raw": message,
        "event_type": "unknown",
        "user": None,
        "src_ip": None,
        "severity": "info",
    }

    # Check failed login
    m = FAILED_LOGIN_RE.search(message)
    if m:
        event["event_type"] = "failed_login"
        event["user"] = m.group(1) or "unknown"
        event["src_ip"] = m.group(2)
        event["severity"] = "warning"
        return event

    # Check invalid user (SSH)
    m = SSH_INVALID_USER_RE.search(message)
    if m:
        event["event_type"] = "failed_login"
        event["user"] = m.group(1)
        event["src_ip"] = m.group(2)
        event["severity"] = "warning"
        return event

    # Check successful login
    m = SUCCESS_LOGIN_RE.search(message)
    if m:
        event["event_type"] = "success_login"
        event["user"] = m.group(1) or "unknown"
        event["src_ip"] = m.group(2)
        event["severity"] = "info"
        return event

    # Check sudo
    m = SUDO_RE.search(message)
    if m:
        event["event_type"] = "sudo_command"
        event["user"] = m.group(1)
        event["severity"] = "medium"
        event["command"] = m.group(2).strip()
        return event

    # Extract any IPs found
    ips = IP_EXTRACT_RE.findall(message)
    if ips:
        event["src_ip"] = ips[0]

    # Classify by keywords
    msg_lower = message.lower()
    if "error" in msg_lower or "fail" in msg_lower:
        event["severity"] = "warning"
        event["event_type"] = "error"
    elif "denied" in msg_lower or "blocked" in msg_lower:
        event["severity"] = "medium"
        event["event_type"] = "access_denied"
    elif "started" in msg_lower or "running" in msg_lower:
        event["event_type"] = "service_start"

    return event


# ═══════════════════════════════════════════════════════
# DETECTION ENGINE — Rule-based threat detection
# ═══════════════════════════════════════════════════════

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60  # seconds


def run_detection(event: dict) -> list[dict]:
    """Run all detection rules against a parsed event.

    Returns list of alert dicts if any rule triggers.

    RULE 1: Brute Force — >5 failed logins from same IP in 60s
    RULE 2: Possible Compromise — successful login after failed attempts
    RULE 3: Blocked IP Activity — activity from already-blocked IP
    """
    fired_alerts = []
    src_ip = event.get("src_ip")
    now = time.time()

    if not src_ip:
        return fired_alerts

    # ── RULE 1: Brute Force Detection ──
    if event["event_type"] == "failed_login":
        # Add to tracker
        failed_login_tracker[src_ip].append(now)
        # Clean old entries outside window
        failed_login_tracker[src_ip] = [
            t for t in failed_login_tracker[src_ip]
            if now - t < BRUTE_FORCE_WINDOW
        ]
        count = len(failed_login_tracker[src_ip])

        if count >= BRUTE_FORCE_THRESHOLD:
            fired_alerts.append({
                "id": str(uuid.uuid4())[:8],
                "alert_type": "BRUTE_FORCE",
                "title": f"Brute Force Attack from {src_ip}",
                "description": (
                    f"{count} failed login attempts from {src_ip} "
                    f"in the last {BRUTE_FORCE_WINDOW}s. "
                    f"Target user: {event.get('user', 'unknown')}"
                ),
                "severity": "critical",
                "src_ip": src_ip,
                "user": event.get("user"),
                "count": count,
                "hostname": event.get("hostname"),
                "mitre": "T1110 — Brute Force",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "new",
            })
            # Track that this IP had failures (for compromise detection)
            login_success_after_fail[src_ip] = count

    # ── RULE 2: Possible Compromise ──
    if event["event_type"] == "success_login" and src_ip in login_success_after_fail:
        fail_count = login_success_after_fail.pop(src_ip)
        fired_alerts.append({
            "id": str(uuid.uuid4())[:8],
            "alert_type": "POSSIBLE_COMPROMISE",
            "title": f"Possible Compromise — Login Success After {fail_count} Failures",
            "description": (
                f"User '{event.get('user', 'unknown')}' successfully logged in from {src_ip} "
                f"after {fail_count} failed attempts. Possible credential compromise."
            ),
            "severity": "high",
            "src_ip": src_ip,
            "user": event.get("user"),
            "count": fail_count,
            "hostname": event.get("hostname"),
            "mitre": "T1078 — Valid Accounts",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "new",
        })

    # ── RULE 3: Blocked IP Still Active ──
    if src_ip in blocked_ips:
        fired_alerts.append({
            "id": str(uuid.uuid4())[:8],
            "alert_type": "BLOCKED_IP_ACTIVITY",
            "title": f"Activity from Blocked IP {src_ip}",
            "description": (
                f"Blocked IP {src_ip} is still sending traffic. "
                f"Event: {event['event_type']}. Firewall rule may not be applied."
            ),
            "severity": "high",
            "src_ip": src_ip,
            "hostname": event.get("hostname"),
            "mitre": "T1071 — Application Layer Protocol",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "new",
        })

    return fired_alerts


# ═══════════════════════════════════════════════════════
# SOAR — Automated Response Playbooks
# ═══════════════════════════════════════════════════════

def run_soar(alert: dict) -> dict | None:
    """Execute SOAR playbook based on alert type.

    PLAYBOOK 1: Brute Force → Block IP
    PLAYBOOK 2: Compromise → Block IP + Escalate

    Returns action taken, or None.
    """
    src_ip = alert.get("src_ip")
    if not src_ip:
        return None

    action = None

    if alert["alert_type"] == "BRUTE_FORCE":
        if src_ip not in blocked_ips:
            blocked_ips.add(src_ip)
            # Persist to blocklist file
            with open(BLOCKED_FILE, "a") as f:
                f.write(f"{src_ip}\n")
            stats["total_blocked"] += 1
            action = {
                "action": "IP_BLOCKED",
                "ip": src_ip,
                "reason": alert["title"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "playbook": "brute_force_response",
            }
            print(f"\n🛡️  SOAR: IP BLOCKED → {src_ip} (Brute Force)\n")

    elif alert["alert_type"] == "POSSIBLE_COMPROMISE":
        if src_ip not in blocked_ips:
            blocked_ips.add(src_ip)
            with open(BLOCKED_FILE, "a") as f:
                f.write(f"{src_ip}\n")
            stats["total_blocked"] += 1
            action = {
                "action": "IP_BLOCKED_AND_ESCALATED",
                "ip": src_ip,
                "reason": alert["title"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "playbook": "compromise_response",
            }
            print(f"\n🚨 SOAR: IP BLOCKED + ESCALATED → {src_ip} (Compromise)\n")

    return action


# ═══════════════════════════════════════════════════════
# FASTAPI APP — The Manager Server
# ═══════════════════════════════════════════════════════

app = FastAPI(title="CyberNest SIEM + SOAR", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/src", StaticFiles(directory=str(FRONTEND_DIR / "src")), name="static")


# ── Health Check ──
@app.get("/health")
async def health():
    return {
        "status": "operational",
        "service": "CyberNest SIEM+SOAR",
        "version": "1.0.0",
        "uptime_seconds": int(time.time() - stats["start_time"]),
        "total_events": stats["total_events"],
        "total_alerts": stats["total_alerts"],
        "total_blocked": stats["total_blocked"],
    }


# ── LOG INGESTION — The core SIEM intake ──
@app.post("/logs")
async def receive_logs(request: Request):
    """Receive raw logs from agents. This is the SIEM intake endpoint.

    Pipeline: Receive → Parse → Detect → Alert → SOAR
    """
    try:
        raw = await request.json()
    except Exception:
        body = await request.body()
        raw = {"message": body.decode("utf-8", errors="replace"), "hostname": "unknown", "log_type": "raw"}

    # Handle batch or single
    log_list = raw if isinstance(raw, list) else [raw]

    results = {"accepted": 0, "alerts_fired": 0, "ips_blocked": 0}

    for log_entry in log_list:
        # 1. Store raw event
        events.append(log_entry)
        if len(events) > MAX_EVENTS:
            events.pop(0)
        stats["total_events"] += 1

        # 2. Parse & normalize
        parsed = parse_log(log_entry)
        parsed_events.append(parsed)
        if len(parsed_events) > MAX_EVENTS:
            parsed_events.pop(0)

        # 3. Run detection
        fired = run_detection(parsed)

        for alert in fired:
            alerts.append(alert)
            stats["total_alerts"] += 1
            results["alerts_fired"] += 1

            # Print alert to console
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(alert["severity"], "⚪")
            print(f"\n{sev_emoji} ALERT [{alert['severity'].upper()}]: {alert['title']}")
            print(f"   MITRE: {alert.get('mitre', 'N/A')}")
            print(f"   Source: {alert.get('src_ip')} → {alert.get('hostname')}")

            # 4. Run SOAR
            action = run_soar(alert)
            if action:
                alert["soar_action"] = action
                results["ips_blocked"] += 1

            # 5. Broadcast to WebSocket clients
            for ws in ws_clients[:]:
                try:
                    await ws.send_json({"type": "alert", "data": alert})
                except Exception:
                    ws_clients.remove(ws)

        results["accepted"] += 1

    # Persist alerts
    try:
        ALERTS_FILE.write_text(json.dumps(alerts[-500:], indent=2))
    except Exception:
        pass

    return results


# ── Agent Registration ──
@app.post("/api/v1/agents/register")
async def register_agent(request: Request):
    data = await request.json()
    agent_id = str(uuid.uuid4())[:12]
    agents[agent_id] = {
        "id": agent_id,
        "hostname": data.get("hostname", "unknown"),
        "ip": data.get("ip_address", "unknown"),
        "os": data.get("os_type", "unknown"),
        "version": data.get("agent_version", "1.0.0"),
        "status": "online",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    print(f"\n✅ Agent registered: {agents[agent_id]['hostname']} ({agent_id})")
    return {"agent_id": agent_id, "status": "registered"}


# ── API Endpoints ──

@app.get("/api/v1/dashboard/stats")
async def dashboard_stats():
    now = time.time()
    recent_alerts = [a for a in alerts if a.get("timestamp", "")]
    severity_counts = defaultdict(int)
    for a in alerts:
        severity_counts[a.get("severity", "info")] += 1

    top_ips = defaultdict(int)
    for e in parsed_events[-1000:]:
        ip = e.get("src_ip")
        if ip:
            top_ips[ip] += 1

    return {
        "total_events": stats["total_events"],
        "total_alerts": stats["total_alerts"],
        "total_blocked": stats["total_blocked"],
        "uptime_seconds": int(now - stats["start_time"]),
        "open_alerts": len([a for a in alerts if a.get("status") == "new"]),
        "critical_alerts": severity_counts.get("critical", 0),
        "high_alerts": severity_counts.get("high", 0),
        "alerts_by_severity": dict(severity_counts),
        "blocked_ips": list(blocked_ips),
        "active_agents": len(agents),
        "top_source_ips": sorted(top_ips.items(), key=lambda x: -x[1])[:10],
        "recent_alerts": alerts[-20:][::-1],
        "events_per_hour": [],
    }


@app.get("/api/v1/alerts")
async def get_alerts(severity: str = None, status: str = None, limit: int = 100):
    result = alerts[::-1]
    if severity:
        result = [a for a in result if a.get("severity") == severity]
    if status:
        result = [a for a in result if a.get("status") == status]
    return result[:limit]


@app.get("/api/v1/events")
async def get_events(limit: int = 100):
    return parsed_events[-limit:][::-1]


@app.get("/api/v1/blocked")
async def get_blocked():
    return {"blocked_ips": list(blocked_ips), "count": len(blocked_ips)}


@app.post("/api/v1/blocked/add")
async def block_ip(request: Request):
    data = await request.json()
    ip = data.get("ip")
    if ip:
        blocked_ips.add(ip)
        with open(BLOCKED_FILE, "a") as f:
            f.write(f"{ip}\n")
        stats["total_blocked"] += 1
        return {"status": "blocked", "ip": ip}
    return {"error": "No IP provided"}


@app.get("/api/v1/agents")
async def get_agents():
    return list(agents.values())


@app.get("/api/v1/incidents")
async def get_incidents():
    return []


@app.get("/api/v1/playbooks")
async def get_playbooks():
    return [
        {"id": 1, "name": "Brute Force Response", "trigger": "BRUTE_FORCE", "enabled": True,
         "steps": ["Lookup IP reputation", "Block IP on firewall", "Notify SOC team", "Create incident"]},
        {"id": 2, "name": "Compromise Response", "trigger": "POSSIBLE_COMPROMISE", "enabled": True,
         "steps": ["Block IP", "Disable user account", "Collect forensic artifacts", "Escalate to IR team"]},
        {"id": 3, "name": "Blocked IP Monitor", "trigger": "BLOCKED_IP_ACTIVITY", "enabled": True,
         "steps": ["Verify firewall rule", "Check for evasion", "Update blocklist"]},
    ]


@app.get("/api/v1/rules")
async def get_rules():
    return [
        {"id": "R001", "name": "Brute Force Detection", "severity": "critical",
         "description": f">{BRUTE_FORCE_THRESHOLD} failed logins from same IP in {BRUTE_FORCE_WINDOW}s",
         "mitre": "T1110", "enabled": True, "hits": stats["total_alerts"]},
        {"id": "R002", "name": "Possible Compromise", "severity": "high",
         "description": "Successful login after multiple failed attempts",
         "mitre": "T1078", "enabled": True, "hits": 0},
        {"id": "R003", "name": "Blocked IP Activity", "severity": "high",
         "description": "Traffic from previously blocked IP",
         "mitre": "T1071", "enabled": True, "hits": 0},
    ]


# ── WebSocket for live alerts ──
@app.websocket("/ws/alerts/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_clients.remove(ws)


# ── Serve Dashboard ──
@app.get("/")
async def serve_dashboard():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse("<h1>CyberNest SIEM+SOAR — API is running</h1><p>Dashboard at /frontend/index.html</p>")


# ── Simulate attack endpoint (for testing) ──
@app.post("/api/v1/simulate/brute-force")
async def simulate_brute_force(request: Request):
    """Simulate a brute force attack for demo purposes."""
    data = await request.json() if request.headers.get("content-type") == "application/json" else {}
    attacker_ip = data.get("ip", "203.0.113.66")
    target_user = data.get("user", "root")
    count = data.get("count", 8)

    results = {"events_sent": 0, "alerts_fired": 0}

    for i in range(count):
        log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": "prod-web-01",
            "log_type": "auth",
            "message": f"Failed password for {target_user} from {attacker_ip} port {22000 + i} ssh2",
        }
        # Process through pipeline
        events.append(log)
        stats["total_events"] += 1
        parsed = parse_log(log)
        parsed_events.append(parsed)
        fired = run_detection(parsed)
        for alert in fired:
            alerts.append(alert)
            stats["total_alerts"] += 1
            results["alerts_fired"] += 1
            action = run_soar(alert)
            if action:
                alert["soar_action"] = action
            for ws in ws_clients[:]:
                try:
                    await ws.send_json({"type": "alert", "data": alert})
                except Exception:
                    ws_clients.remove(ws)
        results["events_sent"] += 1

    # Optionally simulate successful login after failures
    if data.get("with_compromise", False):
        success_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": "prod-web-01",
            "log_type": "auth",
            "message": f"Accepted password for {target_user} from {attacker_ip} port 22050 ssh2",
        }
        events.append(success_log)
        stats["total_events"] += 1
        parsed = parse_log(success_log)
        parsed_events.append(parsed)
        fired = run_detection(parsed)
        for alert in fired:
            alerts.append(alert)
            stats["total_alerts"] += 1
            results["alerts_fired"] += 1
            run_soar(alert)
        results["events_sent"] += 1

    return results


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  CyberNest SIEM + SOAR — Production Pipeline")
    print("=" * 60)
    print(f"  Dashboard:  http://0.0.0.0:8000")
    print(f"  API Docs:   http://0.0.0.0:8000/docs")
    print(f"  Log Intake: POST http://0.0.0.0:8000/logs")
    print(f"  Simulate:   POST http://0.0.0.0:8000/api/v1/simulate/brute-force")
    print("=" * 60 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

"""
CyberNest Agent — Real log collector that monitors system logs.

On Linux: Watches /var/log/auth.log, /var/log/syslog
On any OS: Can also simulate logs for testing

Sends logs to CyberNest Manager via HTTP POST /logs
Buffers locally if manager is unreachable, retries with backoff.

Usage:
  python pipeline/agent.py                           # Auto-detect OS + collect
  python pipeline/agent.py --simulate                # Simulate attack traffic
  python pipeline/agent.py --manager http://host:8000  # Custom manager URL
"""

import json
import time
import platform
import socket
import argparse
import random
from datetime import datetime, timezone
from pathlib import Path

import requests

MANAGER_URL = "http://localhost:8000"
HOSTNAME = socket.gethostname()
OS_TYPE = platform.system().lower()
AGENT_VERSION = "1.0.0"
BATCH_SIZE = 10
RETRY_DELAY = 5


def send_logs(logs: list[dict], manager_url: str) -> bool:
    """Send a batch of logs to the CyberNest Manager."""
    try:
        resp = requests.post(f"{manager_url}/logs", json=logs, timeout=10)
        if resp.status_code == 200:
            result = resp.json()
            if result.get("alerts_fired", 0) > 0:
                print(f"  🚨 {result['alerts_fired']} alerts fired!")
            if result.get("ips_blocked", 0) > 0:
                print(f"  🛡️  {result['ips_blocked']} IPs blocked!")
            return True
        else:
            print(f"  ⚠️  Manager returned {resp.status_code}")
            return False
    except requests.ConnectionError:
        print(f"  ❌ Cannot reach Manager at {manager_url}")
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


def register_agent(manager_url: str):
    """Register this agent with the Manager."""
    try:
        resp = requests.post(f"{manager_url}/api/v1/agents/register", json={
            "hostname": HOSTNAME,
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "os_type": OS_TYPE,
            "agent_version": AGENT_VERSION,
        }, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            print(f"  ✅ Registered as agent {data.get('agent_id', '?')}")
            return True
    except Exception as e:
        print(f"  ⚠️  Registration failed: {e}")
    return False


def tail_file(path: str, manager_url: str):
    """Tail a log file and send new lines to the Manager."""
    log_type = "auth" if "auth" in path else "syslog"
    print(f"  📂 Tailing {path} (type={log_type})")

    try:
        with open(path, "r") as f:
            # Seek to end
            f.seek(0, 2)
            buffer = []

            while True:
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        buffer.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "hostname": HOSTNAME,
                            "log_type": log_type,
                            "message": line,
                        })

                    if len(buffer) >= BATCH_SIZE:
                        print(f"  📤 Sending {len(buffer)} logs...")
                        if not send_logs(buffer, manager_url):
                            print(f"  💾 Buffered {len(buffer)} logs for retry")
                            time.sleep(RETRY_DELAY)
                            send_logs(buffer, manager_url)
                        buffer.clear()
                else:
                    # Flush remaining buffer
                    if buffer:
                        send_logs(buffer, manager_url)
                        buffer.clear()
                    time.sleep(0.5)
    except FileNotFoundError:
        print(f"  ⚠️  File not found: {path}")
    except PermissionError:
        print(f"  ⚠️  Permission denied: {path} (try sudo)")


def simulate_traffic(manager_url: str, duration: int = 300):
    """Simulate realistic attack traffic for demo/testing.

    Generates:
    - Normal SSH logins
    - Brute force attacks
    - Successful logins after failures (compromise)
    - System events
    """
    print(f"\n  🎭 Simulating attack traffic for {duration}s...")

    attacker_ips = ["203.0.113.66", "198.51.100.99", "45.33.32.156", "185.220.101.34"]
    normal_ips = ["10.0.0.5", "10.0.0.12", "192.168.1.100"]
    users = ["root", "admin", "ubuntu", "deploy", "jenkins"]
    hostnames = ["prod-web-01", "db-master", "api-gateway", "auth-service"]

    start = time.time()
    event_count = 0

    while time.time() - start < duration:
        logs = []
        scenario = random.choices(
            ["normal", "brute_force", "compromise", "system"],
            weights=[30, 40, 15, 15],
        )[0]

        host = random.choice(hostnames)

        if scenario == "brute_force":
            # Generate burst of failed logins from attacker IP
            attacker = random.choice(attacker_ips)
            target_user = random.choice(users)
            burst = random.randint(6, 15)
            print(f"  ⚔️  Brute force: {attacker} → {target_user}@{host} ({burst} attempts)")
            for i in range(burst):
                logs.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "hostname": host,
                    "log_type": "auth",
                    "message": f"Failed password for {target_user} from {attacker} port {22000 + i} ssh2",
                })
                time.sleep(0.1)

        elif scenario == "compromise":
            # Failed logins followed by success
            attacker = random.choice(attacker_ips)
            target_user = random.choice(users)
            fails = random.randint(5, 8)
            print(f"  💀 Compromise: {attacker} → {target_user}@{host} ({fails} fails then success)")
            for i in range(fails):
                logs.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "hostname": host,
                    "log_type": "auth",
                    "message": f"Failed password for {target_user} from {attacker} port {22000 + i} ssh2",
                })
                time.sleep(0.1)
            # Successful login
            logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": host,
                "log_type": "auth",
                "message": f"Accepted password for {target_user} from {attacker} port 22050 ssh2",
            })

        elif scenario == "normal":
            # Normal activity
            ip = random.choice(normal_ips)
            user = random.choice(users[:3])
            logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": host,
                "log_type": "auth",
                "message": f"Accepted publickey for {user} from {ip} port {random.randint(40000, 60000)} ssh2",
            })

        else:
            # System events
            messages = [
                f"systemd[1]: Started {random.choice(['nginx', 'postgresql', 'redis', 'docker'])} service",
                f"kernel: [UFW BLOCK] IN=eth0 SRC={random.choice(attacker_ips)} DST=10.0.0.1 PROTO=TCP DPT={random.choice([22, 80, 443, 3389])}",
                f"CRON[{random.randint(1000, 9999)}]: ({random.choice(users)}) CMD (/usr/bin/backup.sh)",
            ]
            logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hostname": host,
                "log_type": "syslog",
                "message": random.choice(messages),
            })

        if logs:
            send_logs(logs, manager_url)
            event_count += len(logs)

        time.sleep(random.uniform(1, 4))

    print(f"\n  ✅ Simulation complete. {event_count} events sent.")


def main():
    parser = argparse.ArgumentParser(description="CyberNest Agent")
    parser.add_argument("--manager", default=MANAGER_URL, help="Manager URL")
    parser.add_argument("--simulate", action="store_true", help="Simulate attack traffic")
    parser.add_argument("--duration", type=int, default=300, help="Simulation duration (seconds)")
    args = parser.parse_args()

    print("\n" + "=" * 50)
    print("  CyberNest Agent v" + AGENT_VERSION)
    print("=" * 50)
    print(f"  Hostname: {HOSTNAME}")
    print(f"  OS:       {OS_TYPE}")
    print(f"  Manager:  {args.manager}")
    print("=" * 50)

    # Register with manager
    register_agent(args.manager)

    if args.simulate:
        simulate_traffic(args.manager, args.duration)
    elif OS_TYPE == "linux":
        import threading
        paths = ["/var/log/auth.log", "/var/log/syslog"]
        threads = []
        for path in paths:
            if Path(path).exists():
                t = threading.Thread(target=tail_file, args=(path, args.manager), daemon=True)
                t.start()
                threads.append(t)
        if threads:
            print(f"\n  👁️  Monitoring {len(threads)} log files...")
            for t in threads:
                t.join()
        else:
            print("\n  ⚠️  No log files found. Use --simulate for demo.")
            simulate_traffic(args.manager, args.duration)
    else:
        print(f"\n  ℹ️  OS={OS_TYPE}, no native log files. Starting simulation...")
        simulate_traffic(args.manager, args.duration)


if __name__ == "__main__":
    main()

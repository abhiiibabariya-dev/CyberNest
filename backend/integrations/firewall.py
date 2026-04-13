"""Firewall integration: iptables, AWS NACL."""
import asyncio, subprocess
from loguru import logger
from core.config import settings

async def block_ip_iptables(ip: str, duration: int = 86400) -> dict:
    try:
        def _run():
            r1 = subprocess.run(["iptables","-I","INPUT","1","-s",ip,"-j","DROP",
                "-m","comment","--comment",f"CyberNest-{ip}"], capture_output=True, text=True)
            r2 = subprocess.run(["iptables","-I","OUTPUT","1","-d",ip,"-j","DROP",
                "-m","comment","--comment",f"CyberNest-{ip}"], capture_output=True, text=True)
            return r1, r2
        r1, r2 = await asyncio.get_event_loop().run_in_executor(None, _run)
        if r1.returncode == 0 and r2.returncode == 0:
            logger.warning(f"[FIREWALL] Blocked {ip} via iptables")
            return {"status": "blocked", "ip": ip, "method": "iptables"}
        return {"status": "error", "ip": ip, "error": r1.stderr or r2.stderr}
    except FileNotFoundError:
        return {"status": "error", "ip": ip, "error": "iptables not found — run as root"}
    except Exception as e:
        return {"status": "error", "ip": ip, "error": str(e)}

async def block_ip(ip: str, duration: int = 86400) -> dict:
    fw = settings.FIREWALL_TYPE.lower()
    if fw == "iptables": return await block_ip_iptables(ip, duration)
    logger.warning(f"[FIREWALL] SIMULATED block {ip} (FIREWALL_TYPE={fw})")
    return {"status": "simulated", "ip": ip, "note": f"Set CYBERNEST_FIREWALL_TYPE=iptables in .env"}

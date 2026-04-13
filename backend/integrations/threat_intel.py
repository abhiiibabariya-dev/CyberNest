"""Real threat intel: VirusTotal + AbuseIPDB."""
import asyncio, httpx, time
from loguru import logger
from core.config import settings

_cache: dict = {}
CACHE_TTL = 3600

def _get(key):
    e = _cache.get(key)
    return e["data"] if e and time.time() - e["ts"] < CACHE_TTL else None

def _set(key, data):
    _cache[key] = {"data": data, "ts": time.time()}

async def lookup_virustotal(ioc: str, ioc_type: str = "ip") -> dict:
    if not settings.VIRUSTOTAL_API_KEY:
        return {"source": "virustotal", "status": "no_api_key", "ioc": ioc}
    key = f"vt:{ioc_type}:{ioc}"
    if c := _get(key): return c
    urls = {"ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
            "hash": f"https://www.virustotal.com/api/v3/files/{ioc}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(urls.get(ioc_type, urls["ip"]),
                                  headers={"x-apikey": settings.VIRUSTOTAL_API_KEY})
            if r.status_code == 200:
                stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                result = {"source": "virustotal", "ioc": ioc,
                          "malicious": stats.get("malicious", 0),
                          "suspicious": stats.get("suspicious", 0),
                          "harmless": stats.get("harmless", 0),
                          "verdict": "malicious" if stats.get("malicious",0)>2 else
                                     "suspicious" if stats.get("suspicious",0)>2 else "clean",
                          "status": "ok"}
                _set(key, result); return result
            return {"source": "virustotal", "ioc": ioc, "status": f"http_{r.status_code}"}
    except Exception as e:
        return {"source": "virustotal", "ioc": ioc, "status": "error", "error": str(e)}

async def lookup_abuseipdb(ip: str) -> dict:
    if not settings.ABUSEIPDB_API_KEY:
        return {"source": "abuseipdb", "status": "no_api_key", "ip": ip}
    key = f"abuse:{ip}"
    if c := _get(key): return c
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90})
            if r.status_code == 200:
                d = r.json().get("data", {})
                result = {"source": "abuseipdb", "ip": ip,
                          "abuse_score": d.get("abuseConfidenceScore", 0),
                          "country": d.get("countryCode", ""),
                          "isp": d.get("isp", ""),
                          "total_reports": d.get("totalReports", 0),
                          "is_tor": d.get("isTor", False),
                          "verdict": "malicious" if d.get("abuseConfidenceScore",0)>75 else
                                     "suspicious" if d.get("abuseConfidenceScore",0)>25 else "clean",
                          "status": "ok"}
                _set(key, result); return result
            return {"source": "abuseipdb", "ip": ip, "status": f"http_{r.status_code}"}
    except Exception as e:
        return {"source": "abuseipdb", "ip": ip, "status": "error", "error": str(e)}

async def enrich_ioc(ioc: str, ioc_type: str = "ip") -> dict:
    tasks = [lookup_virustotal(ioc, ioc_type)]
    if ioc_type == "ip":
        tasks.append(lookup_abuseipdb(ioc))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    enriched = {"ioc": ioc, "type": ioc_type, "sources": [], "verdict": "unknown"}
    for r in results:
        if isinstance(r, Exception): continue
        enriched["sources"].append(r)
        v = r.get("verdict", "unknown")
        if v == "malicious": enriched["verdict"] = "malicious"
        elif v == "suspicious" and enriched["verdict"] != "malicious": enriched["verdict"] = "suspicious"
        elif v == "clean" and enriched["verdict"] == "unknown": enriched["verdict"] = "clean"
    return enriched

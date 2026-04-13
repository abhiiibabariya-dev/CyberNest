"""SOAR Playbook Engine — real actions, template resolution, conditional steps."""
import yaml, asyncio
from datetime import datetime, timezone
from loguru import logger
from core.config import settings
from integrations.threat_intel import enrich_ioc
from integrations.notifications import notify
from integrations.firewall import block_ip

def _resolve(value, context):
    if not isinstance(value, str): return value
    for k, v in context.items():
        value = value.replace(f"{{{{{k}}}}}", str(v) if v else "")
    return value

def _resolve_params(params, context):
    return {k: _resolve(v, context) if isinstance(v, str) else
               _resolve_params(v, context) if isinstance(v, dict) else v
            for k, v in params.items()}

async def action_log(params, context):
    msg = _resolve(params.get("message","Playbook step executed"), context)
    logger.info(f"[PLAYBOOK] LOG: {msg}")
    return {"status": "logged", "message": msg}

async def action_block_ip(params, context):
    ip = _resolve(params.get("ip",""), context) or context.get("src_ip")
    if not ip: return {"status": "skipped", "reason": "No IP in context"}
    return await block_ip(ip, int(params.get("duration", 86400)))

async def action_isolate_host(params, context):
    hostname = _resolve(params.get("hostname",""), context) or context.get("hostname")
    if not hostname: return {"status": "skipped", "reason": "No hostname in context"}
    logger.warning(f"[PLAYBOOK] ISOLATE HOST: {hostname} — configure EDR API")
    return {"status": "isolation_requested", "hostname": hostname, "note": "Configure EDR integration"}

async def action_disable_user(params, context):
    username = _resolve(params.get("username",""), context) or context.get("user")
    if not username: return {"status": "skipped", "reason": "No username in context"}
    logger.warning(f"[PLAYBOOK] DISABLE USER: {username} — configure AD/Okta")
    return {"status": "disable_requested", "username": username}

async def action_enrich_ioc(params, context):
    ioc = _resolve(params.get("ioc",""), context) or context.get("src_ip")
    ioc_type = params.get("type", "ip")
    if not ioc: return {"status": "skipped", "reason": "No IOC value"}
    result = await enrich_ioc(ioc, ioc_type)
    context["ioc_verdict"] = result.get("verdict","unknown")
    context["enrichment"] = result
    return result

async def action_send_notification(params, context):
    p = _resolve_params(params, context)
    return await notify(p.get("channel","slack"), p.get("message","CyberNest Alert"),
                        p.get("severity") or context.get("severity","medium"),
                        p.get("subject"))

async def action_create_ticket(params, context):
    p = _resolve_params(params, context)
    title = p.get("title","CyberNest Incident")
    logger.info(f"[PLAYBOOK] CREATE TICKET: {title}")
    return {"status": "created", "title": title, "note": "Configure Jira/TheHive in integrations/"}

async def action_virustotal_lookup(params, context):
    from integrations.threat_intel import lookup_virustotal
    ioc = _resolve(params.get("target",""), context) or context.get("src_ip")
    result = await lookup_virustotal(ioc, params.get("type","ip"))
    context["vt_result"] = result; return result

async def action_abuseipdb_check(params, context):
    from integrations.threat_intel import lookup_abuseipdb
    ip = _resolve(params.get("ip",""), context) or context.get("src_ip")
    result = await lookup_abuseipdb(ip)
    context["abuse_result"] = result; return result

ACTIONS = {
    "log": action_log, "block_ip": action_block_ip, "firewall_block_ip": action_block_ip,
    "isolate_host": action_isolate_host, "disable_user": action_disable_user,
    "enrich_ioc": action_enrich_ioc, "send_notification": action_send_notification,
    "notify": action_send_notification, "create_ticket": action_create_ticket,
    "virustotal_lookup": action_virustotal_lookup, "abuseipdb_check": action_abuseipdb_check,
}

def _check_condition(condition, context):
    if not condition: return True
    try:
        cond = _resolve(condition, context)
        return bool(eval(cond, {"__builtins__": {}}, {k:v for k,v in context.items() if not callable(v)}))
    except Exception as e:
        logger.warning(f"Condition eval failed: {e}"); return True

async def execute_playbook(playbook: dict, context: dict) -> dict:
    results = []
    name = playbook.get("name","Unknown")
    steps = playbook.get("steps",[])
    logger.info(f"[PLAYBOOK] Starting: {name} ({len(steps)} steps)")
    for i, step in enumerate(steps):
        step_name = step.get("name", f"Step {i+1}")
        action_type = step.get("action")
        params = step.get("params", step.get("input", {}))
        condition = step.get("condition")
        if condition and not _check_condition(condition, context):
            results.append({"step":step_name,"status":"skipped","reason":f"Condition not met: {condition}"})
            continue
        handler = ACTIONS.get(action_type)
        if not handler:
            results.append({"step":step_name,"status":"error","reason":f"Unknown action: {action_type}"})
            continue
        try:
            result = await asyncio.wait_for(handler(params, context), timeout=step.get("timeout",60))
            result["step"] = step_name
            output_key = step.get("output")
            if output_key: context[output_key] = result
        except asyncio.TimeoutError:
            result = {"step":step_name,"status":"timeout","reason":f"Exceeded {step.get('timeout',60)}s"}
        except Exception as e:
            result = {"step":step_name,"status":"error","reason":str(e)}
            logger.error(f"[PLAYBOOK] Step '{step_name}' failed: {e}")
        if result.get("status") in ("error","timeout") and step.get("on_failure") == "abort":
            results.append(result)
            return {"playbook":name,"status":"aborted","steps_completed":i,"results":results}
        results.append(result)
    return {"playbook":name,"status":"completed","steps_completed":len(steps),"results":results}

"""Real notifications: Slack, Email, PagerDuty."""
import httpx, smtplib, asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger
from core.config import settings

async def send_slack(message: str, channel: str = "#soc-alerts", severity: str = "medium") -> dict:
    if not settings.SLACK_WEBHOOK_URL:
        return {"status": "no_webhook_configured"}
    colors = {"critical":"#dc2626","high":"#ea580c","medium":"#ca8a04","low":"#2563eb","info":"#6b7280"}
    payload = {"attachments": [{"color": colors.get(severity.lower(),"#6b7280"),
        "title": f"CyberNest Alert — {severity.upper()}", "text": message,
        "footer": "CyberNest SIEM", "ts": int(__import__("time").time())}]}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(settings.SLACK_WEBHOOK_URL, json=payload)
            return {"status": "sent"} if r.status_code == 200 else {"status": f"error_{r.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def send_email(subject: str, body: str, to: str = None) -> dict:
    if not settings.SMTP_HOST or not settings.SMTP_USER:
        return {"status": "smtp_not_configured"}
    recipient = to or settings.SMTP_USER
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[CyberNest Alert] {subject}"
        msg["From"] = settings.SMTP_FROM
        msg["To"] = recipient
        msg.attach(MIMEText(body, "plain"))
        def _send():
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as s:
                s.starttls(); s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                s.sendmail(settings.SMTP_FROM, recipient, msg.as_string())
        await asyncio.get_event_loop().run_in_executor(None, _send)
        return {"status": "sent", "to": recipient}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def send_pagerduty(title: str, details: str, severity: str = "error") -> dict:
    if not settings.PAGERDUTY_INTEGRATION_KEY:
        return {"status": "no_pd_key_configured"}
    sev_map = {"critical":"critical","high":"error","medium":"warning","low":"info"}
    payload = {"routing_key": settings.PAGERDUTY_INTEGRATION_KEY, "event_action": "trigger",
               "payload": {"summary": title, "severity": sev_map.get(severity.lower(),"error"),
                           "source": "CyberNest SIEM", "custom_details": {"details": details}}}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post("https://events.pagerduty.com/v2/enqueue", json=payload)
            return {"status": "triggered"} if r.status_code in (200,202) else {"status": f"error_{r.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def notify(channel: str, message: str, severity: str = "medium", subject: str = None) -> dict:
    ch = channel.lower()
    if ch in ("slack","soc-alerts","#soc-alerts"): return await send_slack(message, severity=severity)
    if ch == "email": return await send_email(subject or message[:80], message)
    if ch == "pagerduty": return await send_pagerduty(subject or message[:80], message, severity)
    if settings.SLACK_WEBHOOK_URL: return await send_slack(message, channel, severity)
    logger.info(f"[NOTIFY] [{channel}] {message}")
    return {"status": "logged_only"}

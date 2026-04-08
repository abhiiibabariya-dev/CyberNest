"""
CyberNest SOAR Action -- Email Notification.

Sends an HTML-formatted email via SMTP with Jinja2 template substitution
for alert data and playbook step outputs.
"""

from __future__ import annotations

import asyncio
import os
import re
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import partial
from typing import Any

from soar.actions import BaseAction, register_action


SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "cybernest-soar@localhost")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")


def _render_template(template: str, variables: dict[str, Any]) -> str:
    """Replace {{variable}} placeholders with context values."""
    def _resolve(match: re.Match) -> str:
        path = match.group(1).strip()
        parts = path.split(".")
        value: Any = variables
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            else:
                value = getattr(value, part, "")
        return str(value) if value is not None else ""

    return re.sub(r"\{\{(.+?)\}\}", _resolve, template)


_DEFAULT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; padding: 20px; }}
  .container {{ max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
  .header {{ background: {header_color}; color: #fff; padding: 16px 24px; }}
  .header h2 {{ margin: 0; font-size: 18px; }}
  .body {{ padding: 24px; }}
  .field {{ margin-bottom: 12px; }}
  .field-label {{ font-weight: 600; color: #555; font-size: 12px; text-transform: uppercase; }}
  .field-value {{ color: #222; font-size: 14px; margin-top: 2px; }}
  .footer {{ padding: 16px 24px; background: #f9f9f9; font-size: 11px; color: #999; border-top: 1px solid #eee; }}
  .severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; color: #fff; }}
  .severity-critical {{ background: #dc3545; }}
  .severity-high {{ background: #fd7e14; }}
  .severity-medium {{ background: #ffc107; color: #333; }}
  .severity-low {{ background: #28a745; }}
</style>
</head>
<body>
<div class="container">
  <div class="header"><h2>{title}</h2></div>
  <div class="body">
    <p>{message}</p>
    <div class="field">
      <div class="field-label">Severity</div>
      <div class="field-value"><span class="severity severity-{severity}">{severity}</span></div>
    </div>
    <div class="field">
      <div class="field-label">Rule</div>
      <div class="field-value">{rule_name}</div>
    </div>
    <div class="field">
      <div class="field-label">Source IP</div>
      <div class="field-value">{source_ip}</div>
    </div>
    <div class="field">
      <div class="field-label">Hostname</div>
      <div class="field-value">{hostname}</div>
    </div>
    <div class="field">
      <div class="field-label">Alert ID</div>
      <div class="field-value">{alert_id}</div>
    </div>
    <div class="field">
      <div class="field-label">Playbook</div>
      <div class="field-value">{playbook}</div>
    </div>
  </div>
  <div class="footer">
    This is an automated notification from CyberNest SOAR. Execution ID: {execution_id}
  </div>
</div>
</body>
</html>
"""


def _sync_send_email(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    use_tls: bool,
    from_addr: str,
    to_addrs: list[str],
    cc_addrs: list[str],
    subject: str,
    html_body: str,
    plain_body: str,
) -> dict[str, Any]:
    """Blocking SMTP send."""
    msg = MIMEMultipart("alternative")
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg["Subject"] = subject

    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    all_recipients = to_addrs + cc_addrs

    if use_tls:
        context = ssl.create_default_context()
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
    else:
        server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        server.ehlo()

    try:
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.sendmail(from_addr, all_recipients, msg.as_string())
    finally:
        server.quit()

    return {"sent_to": all_recipients, "subject": subject}


@register_action
class EmailNotify(BaseAction):
    """Send an HTML email notification via SMTP."""

    name = "email_notify"
    description = (
        "Send an HTML-formatted email via SMTP with template variable "
        "substitution for alert data and playbook outputs."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        config = context.get("config", {})

        to: str | list[str] = params.get("to", "")
        cc: str | list[str] = params.get("cc", "")
        subject: str = params.get("subject", "CyberNest SOAR Alert")
        message: str = params.get("message", "")
        html_template: str = params.get("html_template", "")

        smtp_host = params.get("smtp_host") or config.get("smtp_host") or SMTP_HOST
        smtp_port = int(params.get("smtp_port") or config.get("smtp_port") or SMTP_PORT)
        smtp_user = params.get("smtp_user") or config.get("smtp_user") or SMTP_USER
        smtp_password = params.get("smtp_password") or config.get("smtp_password") or SMTP_PASSWORD
        from_addr = params.get("from") or config.get("smtp_from") or SMTP_FROM
        use_tls = params.get("use_tls", SMTP_USE_TLS)

        # Normalize recipients
        to_addrs = [t.strip() for t in (to if isinstance(to, list) else to.split(",")) if t.strip()]
        cc_addrs = [c.strip() for c in (cc if isinstance(cc, list) else cc.split(",")) if c.strip()]

        if not to_addrs:
            return self.result(False, error="Missing required parameter 'to' (recipients)")
        if not message and not html_template:
            return self.result(False, error="Either 'message' or 'html_template' is required")

        # Build template context
        alert = context.get("alert", {})
        template_vars = {
            "alert": alert,
            "playbook": context.get("playbook_name", ""),
            "execution_id": context.get("execution_id", ""),
            **context.get("step_outputs", {}),
        }

        rendered_subject = _render_template(subject, template_vars)
        rendered_message = _render_template(message, template_vars)

        severity = alert.get("severity", "medium")
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "informational": "#0066FF",
        }

        if html_template:
            html_body = _render_template(html_template, template_vars)
        else:
            html_body = _DEFAULT_HTML_TEMPLATE.format(
                title=rendered_subject,
                message=rendered_message,
                severity=severity,
                header_color=severity_colors.get(severity, "#333"),
                rule_name=alert.get("rule_name", "N/A"),
                source_ip=alert.get("source_ip", "N/A"),
                hostname=alert.get("hostname", "N/A"),
                alert_id=alert.get("alert_id", "N/A"),
                playbook=context.get("playbook_name", "N/A"),
                execution_id=context.get("execution_id", "N/A"),
            )

        plain_body = rendered_message or f"CyberNest SOAR Alert: {rendered_subject}"

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                partial(
                    _sync_send_email,
                    smtp_host,
                    smtp_port,
                    smtp_user,
                    smtp_password,
                    use_tls,
                    from_addr,
                    to_addrs,
                    cc_addrs,
                    rendered_subject,
                    html_body,
                    plain_body,
                ),
            )
        except smtplib.SMTPAuthenticationError as exc:
            return self.result(False, error=f"SMTP authentication failed: {exc}")
        except smtplib.SMTPConnectError as exc:
            return self.result(False, error=f"Cannot connect to SMTP server: {exc}")
        except smtplib.SMTPException as exc:
            return self.result(False, error=f"SMTP error: {exc}")
        except Exception as exc:
            return self.result(False, error=f"Email send failed: {exc}")

        return self.result(
            True,
            output={
                "sent_to": result["sent_to"],
                "subject": result["subject"],
                "message": f"Email sent to {len(result['sent_to'])} recipient(s)",
            },
        )

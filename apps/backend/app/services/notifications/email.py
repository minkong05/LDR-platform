# 📄 apps/backend/app/services/notifications/email.py

from __future__ import annotations

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import structlog
from app.settings import settings

log = structlog.get_logger(__name__)


class EmailService:
    """
    Sends plain-text + HTML email notifications for high/critical alerts.

    Designed to be called synchronously from the detection worker.
    All failures are caught and logged — a failed email must never
    propagate and crash the detection pipeline.

    Usage:
        svc = EmailService()
        svc.send_alert_notification(alert)
    """

    def __init__(self) -> None:
        self._enabled = settings.SMTP_ENABLED
        self._severity_set = settings.alert_severity_set

    def should_notify(self, severity: str) -> bool:
        """Return True if this severity level triggers email."""
        return self._enabled and severity.lower() in self._severity_set

    def send_alert_notification(self, alert: dict) -> bool:
        """
        Send an email notification for a newly written alert.

        Args:
            alert: dict with keys: rule_id, rule_name, severity,
                   source_ip, event_count, risk_score, started_at, ended_at.

        Returns:
            True if email was sent successfully, False otherwise.
            Never raises — errors are logged and swallowed.
        """
        severity = alert.get("severity", "").lower()

        if not self.should_notify(severity):
            log.debug(
                "email_notification_skipped",
                severity=severity,
                reason="below_threshold_or_disabled",
            )
            return False

        try:
            msg = self._build_message(alert)
            self._send(msg)
            log.info(
                "alert_email_sent",
                rule_id=alert.get("rule_id"),
                severity=severity,
                source_ip=alert.get("source_ip"),
                to=settings.SMTP_TO,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            log.error(
                "alert_email_failed",
                error=str(exc),
                rule_id=alert.get("rule_id"),
                severity=severity,
            )
            return False

    # ── Private helpers ─────────────────────────────────────────────────────

    def _build_message(self, alert: dict) -> MIMEMultipart:
        severity = alert.get("severity", "unknown").upper()
        rule_name = alert.get("rule_name", "Unknown Rule")
        source_ip = alert.get("source_ip", "unknown")
        rule_id = alert.get("rule_id", "")
        event_count = alert.get("event_count", 0)
        risk_score = alert.get("risk_score", 0)
        started_at = str(alert.get("started_at", ""))[:19].replace("T", " ")
        ended_at = str(alert.get("ended_at", ""))[:19].replace("T", " ")

        subject = f"[LDR {severity}] {rule_name} — {source_ip}"

        plain = (
            f"LDR Platform Alert\n"
            f"{'=' * 40}\n"
            f"Severity   : {severity}\n"
            f"Rule       : {rule_name} ({rule_id})\n"
            f"Source IP  : {source_ip}\n"
            f"Events     : {event_count}\n"
            f"Risk Score : {risk_score}/100\n"
            f"Window     : {started_at} → {ended_at} UTC\n"
            f"{'=' * 40}\n"
            f"Review this alert in the LDR dashboard.\n"
        )

        # Severity badge colour for HTML email
        colour_map = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#0d6efd",
            "LOW": "#6c757d",
        }
        badge_colour = colour_map.get(severity, "#6c757d")

        html = f"""
<html><body style="font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:24px;">
  <div style="max-width:560px;margin:auto;">
    <h2 style="margin-bottom:4px;">
      <span style="background:{badge_colour};color:#fff;padding:2px 10px;
                   border-radius:4px;font-size:14px;">{severity}</span>
      &nbsp;LDR Alert
    </h2>
    <p style="color:#aaa;margin-top:4px;font-size:13px;">
      Detected by <strong>{rule_id}</strong>
    </p>
    <table style="width:100%;border-collapse:collapse;margin-top:16px;font-size:14px;">
      <tr><td style="padding:6px 0;color:#aaa;width:120px;">Rule</td>
          <td style="padding:6px 0;">{rule_name}</td></tr>
      <tr><td style="padding:6px 0;color:#aaa;">Source IP</td>
          <td style="padding:6px 0;font-family:monospace;">{source_ip}</td></tr>
      <tr><td style="padding:6px 0;color:#aaa;">Events</td>
          <td style="padding:6px 0;">{event_count}</td></tr>
      <tr><td style="padding:6px 0;color:#aaa;">Risk Score</td>
          <td style="padding:6px 0;">{risk_score}/100</td></tr>
      <tr><td style="padding:6px 0;color:#aaa;">Window</td>
          <td style="padding:6px 0;">{started_at} → {ended_at} UTC</td></tr>
    </table>
    <p style="margin-top:20px;font-size:12px;color:#666;">
      Review this alert in the LDR dashboard.
    </p>
  </div>
</body></html>
"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = settings.SMTP_TO
        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html, "html"))
        return msg

    def _send(self, msg: MIMEMultipart) -> None:
        """Open SMTP connection, authenticate, send, close."""
        context = ssl.create_default_context()
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(
                settings.SMTP_FROM,
                settings.SMTP_TO,
                msg.as_string(),
            )

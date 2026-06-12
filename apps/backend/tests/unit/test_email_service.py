# 📄 apps/backend/tests/unit/test_email_service.py

from unittest.mock import MagicMock, patch

from app.services.notifications.email import EmailService


def _alert(severity: str = "high") -> dict:
    return {
        "rule_id": "LDR-WEB-001",
        "rule_name": "Brute force login failures",
        "severity": severity,
        "source_ip": "1.2.3.4",
        "event_count": 15,
        "risk_score": 75,
        "started_at": "2026-01-01T12:00:00+00:00",
        "ended_at": "2026-01-01T12:05:00+00:00",
    }


# ── should_notify ────────────────────────────────────────────────────────────


def test_should_notify_high_is_true():
    svc = EmailService()
    assert svc.should_notify("high") is True


def test_should_notify_critical_is_true():
    svc = EmailService()
    assert svc.should_notify("critical") is True


def test_should_notify_medium_is_false():
    svc = EmailService()
    assert svc.should_notify("medium") is False


def test_should_notify_low_is_false():
    svc = EmailService()
    assert svc.should_notify("low") is False


def test_should_notify_false_when_disabled(monkeypatch):
    svc = EmailService()
    monkeypatch.setattr(svc, "_enabled", False)
    assert svc.should_notify("critical") is False


# ── send_alert_notification ──────────────────────────────────────────────────


@patch("app.services.notifications.email.smtplib.SMTP")
def test_send_high_alert_calls_smtp(mock_smtp_cls):
    mock_server = MagicMock()
    mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
    mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

    svc = EmailService()
    result = svc.send_alert_notification(_alert("high"))

    assert result is True
    mock_server.sendmail.assert_called_once()


@patch("app.services.notifications.email.smtplib.SMTP")
def test_send_critical_alert_calls_smtp(mock_smtp_cls):
    mock_server = MagicMock()
    mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
    mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

    svc = EmailService()
    result = svc.send_alert_notification(_alert("critical"))

    assert result is True
    mock_server.sendmail.assert_called_once()


@patch("app.services.notifications.email.smtplib.SMTP")
def test_send_medium_alert_skipped(mock_smtp_cls):
    svc = EmailService()
    result = svc.send_alert_notification(_alert("medium"))

    assert result is False
    mock_smtp_cls.assert_not_called()


@patch("app.services.notifications.email.smtplib.SMTP")
def test_smtp_failure_returns_false_does_not_raise(mock_smtp_cls):
    """A broken SMTP connection must not crash the worker."""
    mock_smtp_cls.side_effect = ConnectionRefusedError("no smtp server")

    svc = EmailService()
    result = svc.send_alert_notification(_alert("critical"))

    assert result is False  # swallowed, not raised


def test_build_message_subject_contains_severity_and_ip():
    svc = EmailService()
    msg = svc._build_message(_alert("high"))
    assert "HIGH" in msg["Subject"]
    assert "1.2.3.4" in msg["Subject"]


def test_build_message_has_both_plain_and_html_parts():
    svc = EmailService()
    msg = svc._build_message(_alert("critical"))
    content_types = [part.get_content_type() for part in msg.walk()]
    assert "text/plain" in content_types
    assert "text/html" in content_types

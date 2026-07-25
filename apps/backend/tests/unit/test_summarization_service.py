from unittest.mock import MagicMock

from app.services.summarization.service import SummarizationService
from app.settings import settings


def test_summarize_alert_returns_none_when_disabled_and_skips_client(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", "")

    mock_client = MagicMock()
    svc = SummarizationService(client=mock_client)

    result = svc.summarize_alert({"source_ip": "1.2.3.4"}, [], {"score": 0, "label": "low"})

    assert result is None
    mock_client.summarize.assert_not_called()


def test_summarize_alert_delegates_to_client_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", "test-key")

    mock_client = MagicMock()
    mock_client.summarize.return_value = "a summary"
    svc = SummarizationService(client=mock_client)

    alert = {"source_ip": "1.2.3.4", "rule_id": "LDR-WEB-001"}
    result = svc.summarize_alert(alert, [], {"score": 50, "label": "medium"})

    assert result == "a summary"
    mock_client.summarize.assert_called_once()


def test_summarize_alert_returns_none_when_client_fails(monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", "test-key")

    mock_client = MagicMock()
    mock_client.summarize.return_value = None
    svc = SummarizationService(client=mock_client)

    result = svc.summarize_alert({"source_ip": "1.2.3.4"}, [], {"score": 10, "label": "low"})

    assert result is None

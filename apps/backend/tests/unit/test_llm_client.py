from unittest.mock import MagicMock, patch

import httpx
from app.services.summarization.client import LLMClient


def _enabled_client(monkeypatch) -> LLMClient:
    """An LLMClient with the disabled-by-default check bypassed via monkeypatch."""
    client = LLMClient()
    monkeypatch.setattr(client, "_enabled", True)
    monkeypatch.setattr(client, "_provider", "anthropic")
    monkeypatch.setattr(client, "_api_key", "test-api-key")
    monkeypatch.setattr(client, "_model", "claude-haiku-4-5-20251001")
    monkeypatch.setattr(client, "_timeout", 10)
    return client


def test_summarize_returns_none_when_disabled(monkeypatch):
    client = LLMClient()
    monkeypatch.setattr(client, "_enabled", False)
    assert client.summarize("prompt") is None


def test_summarize_returns_none_for_unsupported_provider(monkeypatch):
    client = _enabled_client(monkeypatch)
    monkeypatch.setattr(client, "_provider", "openai")
    assert client.summarize("prompt") is None


@patch("app.services.summarization.client.httpx.Client")
def test_summarize_success_returns_text(mock_client_cls, monkeypatch):
    client = _enabled_client(monkeypatch)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"content": [{"text": "Summary text"}]}

    mock_http = MagicMock()
    mock_http.post.return_value = mock_response
    mock_client_cls.return_value.__enter__.return_value = mock_http
    mock_client_cls.return_value.__exit__.return_value = False

    assert client.summarize("prompt") == "Summary text"


@patch("app.services.summarization.client.httpx.Client")
def test_summarize_non_200_returns_none(mock_client_cls, monkeypatch):
    client = _enabled_client(monkeypatch)

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "internal error"

    mock_http = MagicMock()
    mock_http.post.return_value = mock_response
    mock_client_cls.return_value.__enter__.return_value = mock_http
    mock_client_cls.return_value.__exit__.return_value = False

    assert client.summarize("prompt") is None


@patch("app.services.summarization.client.httpx.Client")
def test_summarize_timeout_returns_none_not_raised(mock_client_cls, monkeypatch):
    client = _enabled_client(monkeypatch)

    mock_http = MagicMock()
    mock_http.post.side_effect = httpx.TimeoutException("timed out")
    mock_client_cls.return_value.__enter__.return_value = mock_http
    mock_client_cls.return_value.__exit__.return_value = False

    assert client.summarize("prompt") is None


@patch("app.services.summarization.client.httpx.Client")
def test_summarize_network_error_returns_none_not_raised(mock_client_cls, monkeypatch):
    client = _enabled_client(monkeypatch)

    mock_http = MagicMock()
    mock_http.post.side_effect = httpx.ConnectError("connection refused")
    mock_client_cls.return_value.__enter__.return_value = mock_http
    mock_client_cls.return_value.__exit__.return_value = False

    assert client.summarize("prompt") is None


@patch("app.services.summarization.client.httpx.Client")
def test_summarize_unexpected_response_shape_returns_none(mock_client_cls, monkeypatch):
    client = _enabled_client(monkeypatch)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"unexpected": "shape"}

    mock_http = MagicMock()
    mock_http.post.return_value = mock_response
    mock_client_cls.return_value.__enter__.return_value = mock_http
    mock_client_cls.return_value.__exit__.return_value = False

    assert client.summarize("prompt") is None

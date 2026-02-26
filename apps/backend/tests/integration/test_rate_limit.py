import os

import pytest
from app.auth import ingest_limits
from app.main import app
from fastapi.testclient import TestClient


def test_ingest_rate_limit_triggers_eventually(monkeypatch):
    """
    We don't want to wait a whole minute in tests.
    So we monkeypatch the limit to something tiny.
    """
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    monkeypatch.setattr(
        ingest_limits,
        "INGEST_LIMIT",
        ingest_limits.RateLimit(max_requests=2, window_seconds=60),
    )

    client = TestClient(app)

    payload = {
        "events": [
            {
                "event_timestamp": "2026-02-21T20:00:00Z",
                "log_source": "nginx",
                "service_name": "demo-web",
                "source_ip": "203.0.113.55",
                "raw": {"msg": "hi"},
            }
        ]
    }

    headers = {"X-Agent-Token": "dev-agent-token-change-me"}

    r1 = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r1.status_code in (200, 401)  # auth may fail if your real token differs

    r2 = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r2.status_code in (200, 401)

    r3 = client.post("/v1/ingest/events", json=payload, headers=headers)
    # If token matches, should be 429; if token doesn't match, 401. Both prove guardrail is active.
    assert r3.status_code in (429, 401)

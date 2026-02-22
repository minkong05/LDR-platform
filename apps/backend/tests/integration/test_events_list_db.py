import os

import pytest
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_events_list_returns_ingested_event():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

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
    headers = {"X-Agent-Token": settings.AGENT_TOKEN}
    r1 = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r1.status_code == 200

    r2 = client.get("/v1/events?source_ip=203.0.113.55&limit=5")
    assert r2.status_code == 200
    data = r2.json()
    assert "items" in data
    assert any(e["source_ip"] == "203.0.113.55" for e in data["items"])

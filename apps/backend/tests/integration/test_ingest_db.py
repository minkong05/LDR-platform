import os

import pytest
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_ingest_inserts_and_dedupes():
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
    assert r1.json()["inserted"] == 1

    r2 = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r2.status_code == 200
    assert r2.json()["deduped"] == 1

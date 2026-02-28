import os

import pytest
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_flask_json_maps_to_normalized_fields():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    client = TestClient(app)
    headers = {"X-Agent-Token": settings.AGENT_TOKEN}

    payload = {
        "events": [
            {
                "event_timestamp": "2026-02-21T20:01:00Z",
                "log_source": "flask",
                "service_name": "demo-web",
                "source_ip": "203.0.113.99",
                "raw": {
                    "ip": "203.0.113.99",
                    "method": "POST",
                    "path": "/login",
                    "status": 401,
                    "user_agent": "Mozilla/5.0",
                    "action": "login_failed",
                    "username": "alice",
                    "route_group": "auth",
                },
            }
        ]
    }

    r = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r.status_code == 200
    assert r.json()["inserted"] == 1

    r2 = client.get("/v1/events?limit=1")
    assert r2.status_code == 200
    item = r2.json()["items"][0]["normalized"]

    assert item["event"]["action"] == "login_failed"
    assert item["event"]["outcome"] == "failure"
    assert item["labels"]["route_group"] == "auth"
    assert item["user"]["name"] == "alice"
    assert item["http"]["request"]["method"] == "POST"
    assert item["url"]["path"] == "/login"

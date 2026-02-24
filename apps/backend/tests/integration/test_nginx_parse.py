import os

import pytest
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_nginx_line_parses_into_normalized_http_fields():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    client = TestClient(app)
    headers = {"X-Agent-Token": settings.AGENT_TOKEN}

    nginx_line = (
        "203.0.113.55 - - [2026-02-21T20:00:00+00:00] "
        '"POST /login HTTP/1.1" 401 530 "-" "Mozilla/5.0"'
    )

    payload = {
        "events": [
            {
                "event_timestamp": "2026-02-21T20:00:00Z",
                "log_source": "nginx",
                "service_name": "demo-web",
                "source_ip": "0.0.0.0",
                "raw": {"nginx_line": nginx_line},
            }
        ]
    }

    r = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r.status_code == 200
    assert r.json()["inserted"] == 1

    r2 = client.get("/v1/events?limit=1")
    assert r2.status_code == 200
    item = r2.json()["items"][0]

    assert item["normalized"]["source"]["ip"] == "203.0.113.55"
    assert item["normalized"]["http"]["request"]["method"] == "POST"
    assert item["normalized"]["url"]["path"] == "/login"
    assert item["normalized"]["http"]["response"]["status_code"] == 401
    assert item["normalized"]["user_agent"]["original"] == "Mozilla/5.0"

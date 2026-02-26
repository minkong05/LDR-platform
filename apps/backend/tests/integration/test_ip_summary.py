import os

import pytest
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_ip_summary_returns_stats():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    client = TestClient(app)
    headers = {"X-Agent-Token": settings.AGENT_TOKEN}

    # Insert two nginx events for same IP with /login and status 401
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
            },
            {
                "event_timestamp": "2026-02-21T20:00:10Z",
                "log_source": "nginx",
                "service_name": "demo-web",
                "source_ip": "0.0.0.0",
                "raw": {"nginx_line": nginx_line},
            },
        ]
    }
    r = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r.status_code == 200

    r2 = client.get("/v1/entities/ip/203.0.113.55")
    assert r2.status_code == 200
    data = r2.json()
    assert data["total_events"] == 2
    assert any(x["key"] == "/login" for x in data["top_paths"])
    assert any(x["key"] == "401" for x in data["status_codes"])

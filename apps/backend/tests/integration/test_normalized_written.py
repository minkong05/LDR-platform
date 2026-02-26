import os

import pytest
from app.db.models.event import Event
from app.db.session import SessionLocal
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient
from sqlalchemy import select

pytestmark = pytest.mark.integration


def test_ingest_writes_normalized():
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
                "raw": {"action": "http_request", "outcome": "success"},
            }
        ]
    }
    headers = {"X-Agent-Token": settings.AGENT_TOKEN}

    r = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r.status_code == 200
    assert r.json()["inserted"] == 1

    db = SessionLocal()
    try:
        ev = db.execute(select(Event)).scalars().first()
        assert ev is not None
        assert ev.normalized is not None
        assert ev.normalized["log"]["source"] == "nginx"
        assert ev.normalized["service"]["name"] == "demo-web"
        assert ev.normalized["source"]["ip"] == "203.0.113.55"
    finally:
        db.close()

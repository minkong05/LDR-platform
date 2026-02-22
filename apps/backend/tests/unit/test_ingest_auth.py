from app.main import app
from fastapi.testclient import TestClient


def test_ingest_rejects_missing_token():
    client = TestClient(app)
    r = client.post("/v1/ingest/events", json={"events": []})
    # Validation may fail first due to empty list, so test with a valid payload but no token:
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
    r = client.post("/v1/ingest/events", json=payload)
    assert r.status_code == 401

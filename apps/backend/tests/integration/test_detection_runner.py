import os
from pathlib import Path

import pytest
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_detection_runner_creates_alert(tmp_path: Path):
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    # Create a test rule in temp directory
    rule_text = """
id: "TEST-001"
name: "Test brute force"
description: ">=3 login_failed in 5m"
enabled: true

match:
  event.action: "login_failed"
  labels.route_group: "auth"
  url.path: "/login"
  http.request.method: "POST"

condition:
  type: threshold
  group_by: ["source.ip"]
  window: "5m"
  count: 3
  cooldown: "10m"

output:
  severity: high
  confidence: medium
  risk_score: 70
  tags: ["test"]
"""
    (tmp_path / "TEST-001.yml").write_text(rule_text.strip(), encoding="utf-8")

    # Ingest 3 flask events that normalize into the match keys
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
            },
            {
                "event_timestamp": "2026-02-21T20:01:10Z",
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
                    "username": "bob",
                    "route_group": "auth",
                },
            },
            {
                "event_timestamp": "2026-02-21T20:01:20Z",
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
                    "username": "carol",
                    "route_group": "auth",
                },
            },
        ]
    }
    r = client.post("/v1/ingest/events", json=payload, headers=headers)
    assert r.status_code == 200

    # Run detection (via CLI module call inside same process)
    from app.db.session import SessionLocal
    from app.services.detection.runner import run_detection_once

    db = SessionLocal()
    try:
        inserted = run_detection_once(db, rules_dir=tmp_path, lookback_minutes=999999)
        assert inserted == 1
    finally:
        db.close()

    # Confirm alert exists via API
    r2 = client.get("/v1/alerts?source_ip=203.0.113.99")
    assert r2.status_code == 200
    assert len(r2.json()["items"]) >= 1

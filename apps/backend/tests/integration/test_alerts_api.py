import os
from datetime import datetime, timezone

import pytest
from app.db.models.alert import Alert as AlertRow
from app.db.session import SessionLocal
from app.main import app
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration


def test_alerts_list_and_patch():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    # Seed one alert row
    db = SessionLocal()
    try:
        a = AlertRow(
            rule_id="LDR-WEB-001",
            rule_name="Brute force login failures",
            severity="high",
            confidence="medium",
            risk_score=70,
            source_ip="203.0.113.55",
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            event_count=10,
            context={"sample": True},
        )
        db.add(a)
        db.commit()
        db.refresh(a)
        alert_id = str(a.id)
    finally:
        db.close()

    client = TestClient(app)

    r = client.get("/v1/alerts?limit=10")
    assert r.status_code == 200
    assert any(x["id"] == alert_id for x in r.json()["items"])

    r2 = client.patch(
        f"/v1/alerts/{alert_id}", json={"status": "closed", "closure_reason": "confirmed"}
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "closed"
    assert r2.json()["closure_reason"] == "confirmed"

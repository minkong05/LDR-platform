# 📄 apps/backend/tests/integration/test_risk_endpoint.py

import os
from datetime import datetime, timezone

import pytest
from app.db.models.alert import Alert as AlertRow
from app.db.session import SessionLocal
from app.main import app
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

CLIENT = TestClient(app)


def _seed_alert(ip: str, severity: str, status: str = "open") -> None:
    db = SessionLocal()
    try:
        row = AlertRow(
            rule_id="LDR-TEST-001",
            rule_name="Test rule",
            severity=severity,
            confidence="medium",
            risk_score=50,
            source_ip=ip,
            started_at=datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            event_count=5,
            status=status,
            context={},
        )
        db.add(row)
        db.commit()
    finally:
        db.close()


def test_risk_endpoint_returns_zero_for_unknown_ip():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    r = CLIENT.get("/v1/entities/ip/9.9.9.9/risk")
    assert r.status_code == 200
    data = r.json()
    assert data["score"] == 0
    assert data["label"] == "none"
    assert data["contributing_alerts"] == 0


def test_risk_endpoint_scores_open_alerts():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "10.0.0.99"
    _seed_alert(ip, severity="high", status="open")
    _seed_alert(ip, severity="medium", status="open")

    r = CLIENT.get(f"/v1/entities/ip/{ip}/risk")
    assert r.status_code == 200
    data = r.json()

    # high(20) + medium(8) = 28 with near-zero decay → 28
    assert data["score"] == 28
    assert data["label"] == "medium"
    assert data["contributing_alerts"] == 2
    assert data["breakdown"]["high"] == 1
    assert data["breakdown"]["medium"] == 1


def test_risk_endpoint_excludes_closed_alerts():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "10.0.0.88"
    _seed_alert(ip, severity="critical", status="closed")
    _seed_alert(ip, severity="low", status="open")

    r = CLIENT.get(f"/v1/entities/ip/{ip}/risk")
    assert r.status_code == 200
    data = r.json()

    # only the low alert counts → score=3
    assert data["score"] == 3
    assert data["contributing_alerts"] == 1

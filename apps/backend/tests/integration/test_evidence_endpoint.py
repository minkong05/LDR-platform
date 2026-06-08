# 📄 apps/backend/tests/integration/test_evidence_endpoint.py

import io
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from app.db.models.alert import Alert as AlertRow
from app.db.models.event import Event as EventRow
from app.db.session import SessionLocal
from app.main import app
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

CLIENT = TestClient(app)
HEADERS = {"X-Agent-Token": settings.AGENT_TOKEN}


# ── Seed helpers ───────────────────────────────────────────────────────────────


def _seed_event(ip: str, ts: datetime, path: str = "/login") -> None:
    db = SessionLocal()
    try:
        import hashlib  # noqa: E401
        import json as _json

        raw = {"service_name": "demo-web", "path": path, "ip": ip}
        h = hashlib.sha256(
            _json.dumps(
                {"ip": ip, "ts": ts.isoformat(), "path": path},
                sort_keys=True,
            ).encode()
        ).hexdigest()
        row = EventRow(
            event_timestamp=ts,
            log_source="flask",
            source_ip=ip,
            raw=raw,
            normalized={
                "@timestamp": ts.isoformat(),
                "source": {"ip": ip},
                "url": {"path": path},
                "event": {"action": "login_failed", "outcome": "failure"},
                "log": {"source": "flask"},
                "service": {"name": "demo-web"},
            },
            dedupe_hash=h,
        )
        db.add(row)
        db.commit()
    finally:
        db.close()


def _seed_alert(ip: str, severity: str = "high", status: str = "open") -> str:
    """Seed one alert and return its id."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        row = AlertRow(
            rule_id="LDR-WEB-001",
            rule_name="Brute force login failures",
            severity=severity,
            confidence="medium",
            risk_score=70,
            source_ip=ip,
            started_at=now,
            ended_at=now,
            event_count=10,
            status=status,
            context={},
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return str(row.id)
    finally:
        db.close()


def _unzip_response(content: bytes) -> dict[str, bytes]:
    """Return {filename_stem: raw_bytes} for all files in the ZIP."""
    result = {}
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        for name in zf.namelist():
            stem = name.split("/")[-1]  # strip folder prefix
            result[stem] = zf.read(name)
    return result


# ── Tests ──────────────────────────────────────────────────────────────────────


def test_evidence_endpoint_returns_zip():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.50"
    _seed_event(ip, datetime.now(timezone.utc))

    r = CLIENT.get(f"/v1/entities/ip/{ip}/evidence")

    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    assert "attachment" in r.headers["content-disposition"]
    assert zipfile.is_zipfile(io.BytesIO(r.content))


def test_evidence_zip_contains_three_files():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.51"
    _seed_event(ip, datetime.now(timezone.utc))
    _seed_alert(ip)

    r = CLIENT.get(f"/v1/entities/ip/{ip}/evidence")
    assert r.status_code == 200

    files = _unzip_response(r.content)
    assert "summary.md" in files
    assert "alerts.json" in files
    assert "events.json" in files


def test_evidence_alerts_json_matches_seeded_alert():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.52"
    alert_id = _seed_alert(ip, severity="critical", status="open")

    r = CLIENT.get(f"/v1/entities/ip/{ip}/evidence")
    assert r.status_code == 200

    files = _unzip_response(r.content)
    alerts = json.loads(files["alerts.json"])

    assert len(alerts) >= 1
    found = next((a for a in alerts if a["id"] == alert_id), None)
    assert found is not None
    assert found["severity"] == "critical"
    assert found["source_ip"] == ip


def test_evidence_events_json_matches_seeded_event():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.53"
    ts = datetime.now(timezone.utc)
    _seed_event(ip, ts, path="/admin")

    r = CLIENT.get(f"/v1/entities/ip/{ip}/evidence")
    assert r.status_code == 200

    files = _unzip_response(r.content)
    events = json.loads(files["events.json"])

    assert len(events) >= 1
    assert any(e["source_ip"] == ip for e in events)


def test_evidence_summary_md_contains_ip():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.54"
    _seed_event(ip, datetime.now(timezone.utc))

    r = CLIENT.get(f"/v1/entities/ip/{ip}/evidence")
    assert r.status_code == 200

    files = _unzip_response(r.content)
    md = files["summary.md"].decode("utf-8")

    assert ip in md
    assert "Risk Assessment" in md
    assert "Alerts" in md
    assert "Events" in md


def test_evidence_time_range_filters_events():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.55"
    now = datetime.now(timezone.utc)

    # One recent event (inside range) and one old event (outside range)
    _seed_event(ip, now, path="/login")
    _seed_event(ip, now - timedelta(days=30), path="/old-path")

    # Request only the last 24 hours
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = CLIENT.get(f"/v1/entities/ip/{ip}/evidence?start={start}")
    assert r.status_code == 200

    files = _unzip_response(r.content)
    events = json.loads(files["events.json"])

    # Only the recent event should appear
    paths = [e.get("normalized", {}).get("url", {}).get("path") for e in events]
    assert "/login" in paths
    assert "/old-path" not in paths


def test_evidence_time_range_filters_alerts():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.56"
    _seed_alert(ip, severity="high", status="open")

    # Request a window in the distant past — alert should not appear
    start = "2020-01-01T00:00:00Z"
    end = "2020-12-31T23:59:59Z"
    r = CLIENT.get(f"/v1/entities/ip/{ip}/evidence?start={start}&end={end}")
    assert r.status_code == 200

    files = _unzip_response(r.content)
    alerts = json.loads(files["alerts.json"])
    assert len(alerts) == 0


def test_evidence_empty_ip_returns_valid_empty_zip():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    # IP that has never been seen — should still return a valid ZIP
    r = CLIENT.get("/v1/entities/ip/198.51.100.99/evidence")
    assert r.status_code == 200

    files = _unzip_response(r.content)
    assert "summary.md" in files

    alerts = json.loads(files["alerts.json"])
    events = json.loads(files["events.json"])
    assert alerts == []
    assert events == []

# apps/backend/tests/integration/test_detection_full_002_006.py

import os
from pathlib import Path

import pytest
from app.db.session import SessionLocal
from app.main import app
from app.services.detection.runner import run_detection_once
from app.settings import settings
from fastapi.testclient import TestClient

pytestmark = pytest.mark.integration

CLIENT = TestClient(app)
HEADERS = {"X-Agent-Token": settings.AGENT_TOKEN}

# ── Shared helpers ─────────────────────────────────────────────────────────────


def _ingest(events: list[dict]) -> None:
    r = CLIENT.post(
        "/v1/ingest/events",
        json={"events": events},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text


def _run(rules_dir: Path, lookback: int = 999_999) -> int:
    db = SessionLocal()
    try:
        return run_detection_once(db, rules_dir=rules_dir, lookback_minutes=lookback)
    finally:
        db.close()


def _assert_alert_exists(rule_id: str, source_ip: str) -> None:
    r = CLIENT.get(f"/v1/alerts?source_ip={source_ip}")
    assert r.status_code == 200
    items = r.json()["items"]
    matching = [a for a in items if a["rule_id"] == rule_id]
    assert (
        len(matching) >= 1
    ), f"Expected alert for {rule_id} from {source_ip}, got: {[a['rule_id'] for a in items]}"


def _rule_file(tmp_path: Path, rule_id: str) -> Path:
    """Copy one rule from the repo rules/ dir into tmp_path for isolation."""
    src = Path("rules") / f"{rule_id}.yml"
    dst = tmp_path / f"{rule_id}.yml"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


# ── LDR-WEB-002: Credential stuffing ──────────────────────────────────────────


def test_integration_web_002(tmp_path: Path):
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.10"
    rules_dir = _rule_file(tmp_path, "LDR-WEB-002")

    # Ingest 20 nginx events returning 401 — each unique via timestamp offset
    from datetime import datetime, timedelta, timezone

    base = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)

    events = []
    for i in range(20):
        ts = (base + timedelta(seconds=i * 4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        nginx_line = (
            f"{ip} - - [2026-03-01T10:00:{i:02d}+00:00] "
            f'"POST /login HTTP/1.1" 401 120 "-" "python-requests/2.31"'
        )
        events.append(
            {
                "event_timestamp": ts,
                "log_source": "nginx",
                "service_name": "demo-web",
                "source_ip": ip,
                "raw": {"nginx_line": nginx_line},
            }
        )

    _ingest(events)
    inserted = _run(rules_dir)
    assert inserted == 1
    _assert_alert_exists("LDR-WEB-002", ip)


# ── LDR-WEB-003: Admin panel probing ──────────────────────────────────────────


def test_integration_web_003(tmp_path: Path):
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.11"
    rules_dir = _rule_file(tmp_path, "LDR-WEB-003")

    from datetime import datetime, timedelta, timezone

    base = datetime(2026, 3, 1, 11, 0, 0, tzinfo=timezone.utc)

    events = []
    for i in range(5):
        ts = (base + timedelta(seconds=i * 30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        nginx_line = (
            f"{ip} - - [2026-03-01T11:00:{i*30:02d}+00:00] "
            f'"GET /admin HTTP/1.1" 403 89 "-" "curl/7.88"'
        )
        events.append(
            {
                "event_timestamp": ts,
                "log_source": "nginx",
                "service_name": "demo-web",
                "source_ip": ip,
                "raw": {"nginx_line": nginx_line},
            }
        )

    _ingest(events)
    inserted = _run(rules_dir)
    assert inserted == 1
    _assert_alert_exists("LDR-WEB-003", ip)


# ── LDR-WEB-004: 404 path scanning ────────────────────────────────────────────


def test_integration_web_004(tmp_path: Path):
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.12"
    rules_dir = _rule_file(tmp_path, "LDR-WEB-004")

    from datetime import datetime, timedelta, timezone

    base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

    events = []
    for i in range(30):
        ts = (base + timedelta(seconds=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        path = f"/probe/path{i}"
        nginx_line = (
            f"{ip} - - [2026-03-01T12:00:{i*5:02d}+00:00] "
            f'"GET {path} HTTP/1.1" 404 0 "-" "gobuster/3.6"'
        )
        events.append(
            {
                "event_timestamp": ts,
                "log_source": "nginx",
                "service_name": "demo-web",
                "source_ip": ip,
                "raw": {"nginx_line": nginx_line},
            }
        )

    _ingest(events)
    inserted = _run(rules_dir)
    assert inserted == 1
    _assert_alert_exists("LDR-WEB-004", ip)


# ── LDR-WEB-005: Login success after brute force ──────────────────────────────


def test_integration_web_005(tmp_path: Path):
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.13"
    rules_dir = _rule_file(tmp_path, "LDR-WEB-005")

    from datetime import datetime, timezone

    ts = datetime(2026, 3, 1, 13, 0, 0, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    events = [
        {
            "event_timestamp": ts,
            "log_source": "flask",
            "service_name": "demo-web",
            "source_ip": ip,
            "raw": {
                "ip": ip,
                "method": "POST",
                "path": "/login",
                "status": 200,
                "action": "login_success",
                "username": "victim_user",
                "route_group": "auth",
            },
        }
    ]

    _ingest(events)
    inserted = _run(rules_dir)
    assert inserted == 1
    _assert_alert_exists("LDR-WEB-005", ip)


# ── LDR-WEB-006: Account enumeration ──────────────────────────────────────────


def test_integration_web_006(tmp_path: Path):
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    ip = "192.0.2.14"
    rules_dir = _rule_file(tmp_path, "LDR-WEB-006")

    from datetime import datetime, timedelta, timezone

    base = datetime(2026, 3, 1, 14, 0, 0, tzinfo=timezone.utc)

    events = []
    for i in range(15):
        ts = (base + timedelta(seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append(
            {
                "event_timestamp": ts,
                "log_source": "flask",
                "service_name": "demo-web",
                "source_ip": ip,
                "raw": {
                    "ip": ip,
                    "method": "POST",
                    "path": "/login",
                    "status": 401,
                    "action": "login_failed",
                    "username": f"user{i}",
                    "route_group": "auth",
                },
            }
        )

    _ingest(events)
    inserted = _run(rules_dir)
    assert inserted == 1
    _assert_alert_exists("LDR-WEB-006", ip)

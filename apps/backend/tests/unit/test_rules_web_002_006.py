# apps/backend/tests/unit/test_rules_web_002_006.py

from pathlib import Path

from app.domain.rules.rule_schema import Rule
from app.services.detection.engine import ThresholdEngine
from app.services.detection.rule_loader import load_rule_file

RULES_DIR = Path("rules")


# ── Helpers ────────────────────────────────────────────────────────────────────
def _load(rule_id: str) -> Rule:
    return load_rule_file(RULES_DIR / f"{rule_id}.yml")


def _engine(rule: Rule) -> ThresholdEngine:
    return ThresholdEngine([rule])


def _ts(offset_seconds: int = 0) -> str:
    """Return a fixed base timestamp offset by N seconds."""
    base = 1_740_168_000  # 2026-02-21T20:00:00Z as epoch
    import datetime

    dt = datetime.datetime.fromtimestamp(base + offset_seconds, tz=datetime.timezone.utc)
    return dt.isoformat()


# ── LDR-WEB-002: Credential stuffing — high 401 rate ──────────────────────────
def _event_002(offset: int, ip: str = "1.2.3.4") -> dict:
    """Nginx-normalized event with http.response.status_code == 401."""
    return {
        "@timestamp": _ts(offset),
        "source": {"ip": ip},
        "http": {
            "request": {"method": "POST"},
            "response": {"status_code": 401},
        },
        "url": {"path": "/login"},
        "event": {"action": "http_request", "outcome": "failure"},
    }


def test_web_002_fires_on_20_events_in_window():
    rule = _load("LDR-WEB-002")
    engine = _engine(rule)
    # 20 events in 90 seconds — inside the 2m window
    events = [_event_002(i * 4) for i in range(20)]
    alerts = engine.process(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LDR-WEB-002"
    assert alerts[0].source_ip == "1.2.3.4"
    assert alerts[0].event_count == 20


def test_web_002_does_not_fire_on_19_events():
    rule = _load("LDR-WEB-002")
    engine = _engine(rule)
    # One short of threshold
    events = [_event_002(i * 4) for i in range(19)]
    alerts = engine.process(events)
    assert alerts == []


def test_web_002_does_not_fire_on_200_status():
    """Events with status 200 must not match a rule keyed on 401."""
    rule = _load("LDR-WEB-002")
    engine = _engine(rule)
    events = []
    for i in range(25):
        e = _event_002(i * 2)
        e["http"]["response"]["status_code"] = 200  # wrong status
        events.append(e)
    alerts = engine.process(events)
    assert alerts == []


def test_web_002_isolates_by_ip():
    """Two IPs each hitting 10 events should not jointly trigger the threshold."""
    rule = _load("LDR-WEB-002")
    engine = _engine(rule)
    events = [_event_002(i * 4, ip="1.1.1.1") for i in range(10)] + [
        _event_002(i * 4, ip="2.2.2.2") for i in range(10)
    ]
    alerts = engine.process(events)
    assert alerts == []


# ── LDR-WEB-003: Admin panel probing ─────────────────────────────────────────
def _event_003(offset: int, ip: str = "5.5.5.5") -> dict:
    """Event hitting /admin and receiving 403."""
    return {
        "@timestamp": _ts(offset),
        "source": {"ip": ip},
        "http": {
            "request": {"method": "GET"},
            "response": {"status_code": 403},
        },
        "url": {"path": "/admin"},
        "event": {"action": "http_request", "outcome": "failure"},
    }


def test_web_003_fires_on_5_admin_403s():
    rule = _load("LDR-WEB-003")
    engine = _engine(rule)
    events = [_event_003(i * 30) for i in range(5)]
    alerts = engine.process(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LDR-WEB-003"
    assert alerts[0].event_count == 5


def test_web_003_does_not_fire_on_4_events():
    rule = _load("LDR-WEB-003")
    engine = _engine(rule)
    events = [_event_003(i * 30) for i in range(4)]
    alerts = engine.process(events)
    assert alerts == []


def test_web_003_does_not_fire_on_wrong_path():
    """403 on /api/secret should not match — rule requires /admin exactly."""
    rule = _load("LDR-WEB-003")
    engine = _engine(rule)
    events = []
    for i in range(10):
        e = _event_003(i * 10)
        e["url"]["path"] = "/api/secret"  # wrong path
        events.append(e)
    alerts = engine.process(events)
    assert alerts == []


def test_web_003_does_not_fire_on_admin_200():
    """A 200 on /admin (successful access) should not match this rule."""
    rule = _load("LDR-WEB-003")
    engine = _engine(rule)
    events = []
    for i in range(10):
        e = _event_003(i * 10)
        e["http"]["response"]["status_code"] = 200  # successful, not probing
        events.append(e)
    alerts = engine.process(events)
    assert alerts == []


# ── LDR-WEB-004: 404 path scanning ────────────────────────────────────────────
def _event_004(offset: int, ip: str = "9.9.9.9", path: str = "/etc/passwd") -> dict:
    """Scanner-style event — varied paths all returning 404."""
    return {
        "@timestamp": _ts(offset),
        "source": {"ip": ip},
        "http": {
            "request": {"method": "GET"},
            "response": {"status_code": 404},
        },
        "url": {"path": path},
        "event": {"action": "http_request", "outcome": "failure"},
    }


def test_web_004_fires_on_30_404s_in_window():
    rule = _load("LDR-WEB-004")
    engine = _engine(rule)
    # 30 events in 3 seconds — well inside the 3m window
    events = [_event_004(i, path=f"/probe/{i}") for i in range(30)]
    alerts = engine.process(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LDR-WEB-004"
    assert alerts[0].event_count == 30


def test_web_004_does_not_fire_on_29_events():
    rule = _load("LDR-WEB-004")
    engine = _engine(rule)
    events = [_event_004(i, path=f"/probe/{i}") for i in range(29)]
    alerts = engine.process(events)
    assert alerts == []


def test_web_004_does_not_fire_on_200_responses():
    """30 successful requests should not look like a scan."""
    rule = _load("LDR-WEB-004")
    engine = _engine(rule)
    events = []
    for i in range(30):
        e = _event_004(i, path=f"/real/{i}")
        e["http"]["response"]["status_code"] = 200
        events.append(e)
    alerts = engine.process(events)
    assert alerts == []


def test_web_004_events_outside_window_do_not_count():
    """Events older than 3m must be evicted from the sliding window."""
    rule = _load("LDR-WEB-004")
    engine = _engine(rule)
    # 20 events early, then 20 events 10 minutes later — neither burst reaches 30
    early = [_event_004(i * 5, path=f"/old/{i}") for i in range(20)]
    late = [_event_004(600 + i * 5, path=f"/new/{i}") for i in range(20)]
    alerts = engine.process(early + late)
    assert alerts == []


# ── LDR-WEB-005: Successful login after brute force ───────────────────────────
def _event_005_success(offset: int, ip: str = "7.7.7.7") -> dict:
    """Flask-normalized login_success event."""
    return {
        "@timestamp": _ts(offset),
        "source": {"ip": ip},
        "http": {
            "request": {"method": "POST"},
            "response": {"status_code": 200},
        },
        "url": {"path": "/login"},
        "event": {"action": "login_success", "outcome": "success"},
        "labels": {"route_group": "auth"},
    }


def _event_005_failure(offset: int, ip: str = "7.7.7.7") -> dict:
    """Flask-normalized login_failed event (should not match LDR-WEB-005)."""
    return {
        "@timestamp": _ts(offset),
        "source": {"ip": ip},
        "http": {
            "request": {"method": "POST"},
            "response": {"status_code": 401},
        },
        "url": {"path": "/login"},
        "event": {"action": "login_failed", "outcome": "failure"},
        "labels": {"route_group": "auth"},
    }


def test_web_005_fires_on_single_login_success():
    """Threshold is 1 — a single login_success triggers immediately."""
    rule = _load("LDR-WEB-005")
    engine = _engine(rule)
    events = [_event_005_success(0)]
    alerts = engine.process(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LDR-WEB-005"
    assert alerts[0].source_ip == "7.7.7.7"


def test_web_005_does_not_fire_on_login_failure():
    """login_failed events must not match a rule keyed on login_success."""
    rule = _load("LDR-WEB-005")
    engine = _engine(rule)
    # Many failures — none should fire LDR-WEB-005
    events = [_event_005_failure(i * 5) for i in range(20)]
    alerts = engine.process(events)
    assert alerts == []


def test_web_005_does_not_fire_on_wrong_route_group():
    """login_success on a non-auth route_group should not match."""
    rule = _load("LDR-WEB-005")
    engine = _engine(rule)
    e = _event_005_success(0)
    e["labels"]["route_group"] = "api"  # wrong group
    alerts = engine.process([e])
    assert alerts == []


def test_web_005_cooldown_prevents_repeated_alerts():
    """After the first alert fires, cooldown of 30m suppresses further ones."""
    rule = _load("LDR-WEB-005")
    engine = _engine(rule)
    # Two successes 5 seconds apart — only one alert
    events = [_event_005_success(0), _event_005_success(5)]
    alerts = engine.process(events)
    assert len(alerts) == 1


# ── LDR-WEB-006: Account enumeration ──────────────────────────────────────────
def _event_006(offset: int, ip: str = "3.3.3.3") -> dict:
    """login_failed + outcome=failure event for enumeration rule."""
    return {
        "@timestamp": _ts(offset),
        "source": {"ip": ip},
        "http": {
            "request": {"method": "POST"},
            "response": {"status_code": 401},
        },
        "url": {"path": "/login"},
        "event": {"action": "login_failed", "outcome": "failure"},
        "labels": {"route_group": "auth"},
    }


def test_web_006_fires_on_15_failures_in_window():
    rule = _load("LDR-WEB-006")
    engine = _engine(rule)
    events = [_event_006(i * 10) for i in range(15)]
    alerts = engine.process(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "LDR-WEB-006"
    assert alerts[0].event_count == 15


def test_web_006_does_not_fire_on_14_events():
    rule = _load("LDR-WEB-006")
    engine = _engine(rule)
    events = [_event_006(i * 10) for i in range(14)]
    alerts = engine.process(events)
    assert alerts == []


def test_web_006_does_not_fire_on_login_success():
    """login_success events must not match — action mismatch."""
    rule = _load("LDR-WEB-006")
    engine = _engine(rule)
    events = []
    for i in range(20):
        e = _event_006(i * 5)
        e["event"]["action"] = "login_success"
        e["event"]["outcome"] = "success"
        events.append(e)
    alerts = engine.process(events)
    assert alerts == []


def test_web_006_different_ips_do_not_combine():
    """Enumeration is per-IP — 8 events from IP A and 7 from IP B must not merge."""
    rule = _load("LDR-WEB-006")
    engine = _engine(rule)
    events = [_event_006(i * 5, ip="10.0.0.1") for i in range(8)] + [
        _event_006(i * 5, ip="10.0.0.2") for i in range(7)
    ]
    alerts = engine.process(events)
    assert alerts == []

from app.domain.rules.rule_schema import Rule
from app.services.detection.engine import ThresholdEngine
from app.services.detection.timeparse import parse_duration


def test_parse_duration():
    assert parse_duration("5m").total_seconds() == 300
    assert parse_duration("2h").total_seconds() == 7200


def test_threshold_triggers_on_3_events():
    rule = Rule.model_validate(
        {
            "id": "T-1",
            "name": "Test rule",
            "description": "x",
            "enabled": True,
            "match": {"event.action": "login_failed"},
            "condition": {
                "type": "threshold",
                "group_by": ["source.ip"],
                "window": "5m",
                "count": 3,
                "cooldown": "10m",
            },
            "output": {"severity": "high", "confidence": "medium", "risk_score": 70, "tags": []},
        }
    )

    engine = ThresholdEngine([rule])

    events = [
        {
            "@timestamp": "2026-02-21T20:00:00Z",
            "event": {"action": "login_failed"},
            "source": {"ip": "1.2.3.4"},
        },
        {
            "@timestamp": "2026-02-21T20:01:00Z",
            "event": {"action": "login_failed"},
            "source": {"ip": "1.2.3.4"},
        },
        {
            "@timestamp": "2026-02-21T20:02:00Z",
            "event": {"action": "login_failed"},
            "source": {"ip": "1.2.3.4"},
        },
    ]

    alerts = engine.process(events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "T-1"
    assert alerts[0].source_ip == "1.2.3.4"
    assert alerts[0].event_count == 3


def test_cooldown_prevents_spam():
    rule = Rule.model_validate(
        {
            "id": "T-2",
            "name": "Cooldown rule",
            "description": "x",
            "enabled": True,
            "match": {"event.action": "login_failed"},
            "condition": {
                "type": "threshold",
                "group_by": ["source.ip"],
                "window": "5m",
                "count": 2,
                "cooldown": "10m",
            },
            "output": {"severity": "high", "confidence": "medium", "risk_score": 70, "tags": []},
        }
    )

    engine = ThresholdEngine([rule])

    events = [
        {
            "@timestamp": "2026-02-21T20:00:00+00:00",
            "event": {"action": "login_failed"},
            "source": {"ip": "9.9.9.9"},
        },
        {
            "@timestamp": "2026-02-21T20:01:00+00:00",
            "event": {"action": "login_failed"},
            "source": {"ip": "9.9.9.9"},
        },
        # second burst within cooldown
        {
            "@timestamp": "2026-02-21T20:02:00+00:00",
            "event": {"action": "login_failed"},
            "source": {"ip": "9.9.9.9"},
        },
        {
            "@timestamp": "2026-02-21T20:03:00+00:00",
            "event": {"action": "login_failed"},
            "source": {"ip": "9.9.9.9"},
        },
    ]

    alerts = engine.process(events)
    assert len(alerts) == 1

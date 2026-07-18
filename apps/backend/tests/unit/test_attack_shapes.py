from datetime import datetime
from pathlib import Path

from app.services.detection.match import rule_matches
from app.services.detection.rule_loader import load_rules
from app.services.normalizer.mapper import normalize_event
from app.services.normalizer.parsers.flask import parse_flask_json
from app.services.normalizer.parsers.nginx import parse_nginx_access_line
from app.services.simulation.attack_shapes import build_events_for_rule, synthetic_ip_for_rule

RULES_DIR = Path("rules")


def _normalize(payload: dict) -> dict:
    """Mirror the ingest router's raw -> parsed -> normalized pipeline."""
    raw = payload["raw"]
    parsed = None

    if payload["log_source"] == "nginx" and raw.get("nginx_line"):
        parsed = parse_nginx_access_line(raw["nginx_line"])

    if payload["log_source"] == "flask":
        parsed = parse_flask_json(raw)

    return normalize_event(
        event_timestamp=datetime.fromisoformat(payload["event_timestamp"]),
        log_source=payload["log_source"],
        service_name=payload["service_name"],
        source_ip=payload["source_ip"],
        raw=raw,
        parsed=parsed,
    )


def test_synthetic_ip_for_rule_is_stable_and_distinct():
    rule_ids = [f"LDR-WEB-00{n}" for n in range(1, 7)]
    ips = {rule_id: synthetic_ip_for_rule(rule_id) for rule_id in rule_ids}
    assert len(set(ips.values())) == len(ips)


def test_every_rule_has_an_attack_shape():
    rules = load_rules(RULES_DIR)
    assert rules, "expected at least one rule to be loaded from rules/"
    for rule in rules:
        payloads = build_events_for_rule(rule)
        assert len(payloads) >= 1


def test_generated_events_satisfy_their_own_rule_at_threshold():
    rules = load_rules(RULES_DIR)
    for rule in rules:
        payloads = build_events_for_rule(rule)

        assert len(payloads) >= rule.condition.count

        matching = [p for p in payloads if rule_matches(_normalize(p), rule.match)]
        assert len(matching) >= rule.condition.count, (
            f"{rule.id}: only {len(matching)} of {len(payloads)} generated events "
            f"matched the rule's own `match` block (need >= {rule.condition.count})"
        )


def test_unknown_rule_id_raises():
    rules = load_rules(RULES_DIR)
    fake_rule = rules[0].model_copy(update={"id": "LDR-WEB-999"})
    try:
        build_events_for_rule(fake_rule)
        raised = False
    except ValueError:
        raised = True
    assert raised

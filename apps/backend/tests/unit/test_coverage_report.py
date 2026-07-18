import json

from app.domain.rules.rule_schema import Rule
from app.services.simulation.report import CoverageReport


def _rule(rule_id: str, *, technique_id: str | None = "T1110") -> Rule:
    mitre = (
        {"tactic": "Credential Access", "technique_id": technique_id, "technique": "Brute Force"}
        if technique_id
        else None
    )
    return Rule.model_validate(
        {
            "id": rule_id,
            "name": f"Rule {rule_id}",
            "description": "x",
            "enabled": True,
            "match": {"event.action": "login_failed"},
            "condition": {
                "type": "threshold",
                "group_by": ["source.ip"],
                "window": "5m",
                "count": 10,
                "cooldown": "10m",
            },
            "output": {
                "severity": "high",
                "confidence": "medium",
                "risk_score": 70,
                "tags": [],
                "mitre": mitre,
            },
        }
    )


def test_build_marks_fired_and_unfired_rules():
    rules = [_rule("LDR-WEB-001"), _rule("LDR-WEB-002", technique_id=None)]
    fired = {"LDR-WEB-001": True}

    report = CoverageReport.build(rules, fired)

    by_id = {rc.rule_id: rc for rc in report.rule_coverage}
    assert by_id["LDR-WEB-001"].fired is True
    assert by_id["LDR-WEB-001"].technique_id == "T1110"
    assert by_id["LDR-WEB-002"].fired is False
    assert by_id["LDR-WEB-002"].technique_id is None


def test_build_lists_uncovered_techniques_from_mitre_reference():
    report = CoverageReport.build([_rule("LDR-WEB-001")], {"LDR-WEB-001": True})

    uncovered_ids = {t["technique_id"] for t in report.uncovered_techniques}
    assert "T1190" in uncovered_ids
    assert all(t["covered_by"] is None for t in report.uncovered_techniques)


def test_to_json_round_trips_fired_state():
    report = CoverageReport.build([_rule("LDR-WEB-001")], {"LDR-WEB-001": True})

    data = json.loads(report.to_json())

    assert data["rules"][0]["rule_id"] == "LDR-WEB-001"
    assert data["rules"][0]["fired"] is True
    assert "uncovered_techniques" in data


def test_to_markdown_reports_fired_summary_and_gaps():
    rules = [_rule("LDR-WEB-001"), _rule("LDR-WEB-002", technique_id=None)]
    fired = {"LDR-WEB-001": True}

    md = CoverageReport.build(rules, fired).to_markdown()

    assert "1/2 rules fired" in md
    assert "LDR-WEB-001" in md
    assert "T1110" in md
    assert "Known gaps" in md
    assert "T1190" in md

from pathlib import Path

import pytest
from app.services.detection.rule_loader import RuleLoadError, load_rule_file, load_rules


def test_load_valid_rule():
    path = Path("rules/LDR-WEB-001.yml")
    r = load_rule_file(path)
    assert r.id == "LDR-WEB-001"
    assert r.condition.count == 10
    assert r.output.severity in {"low", "medium", "high", "critical"}


def test_invalid_rule_fails(tmp_path: Path):
    bad = tmp_path / "bad.yml"
    bad.write_text("id: 123\nname: x\n", encoding="utf-8")  # missing required fields, wrong types
    with pytest.raises(RuleLoadError):
        load_rule_file(bad)


def test_load_rules_filters_disabled(tmp_path: Path):
    (tmp_path / "a.yml").write_text(
        """
        id: "R1"
        name: "r1"
        description: "d"
        enabled: true
        match: {}
        condition: {
                type: threshold, 
                group_by: ["source.ip"], 
                window: "5m", 
                count: 1, 
                cooldown: "10m"}
        output: {severity: low, confidence: low, risk_score: 1, tags: []}
        """,
        encoding="utf-8",
    )

    (tmp_path / "b.yml").write_text(
        """
        id: "R2"
        name: "r2"
        description: "d"
        enabled: false
        match: {}
        condition: {
                type: threshold, 
                group_by: ["source.ip"], 
                window: "5m", count: 1, 
                cooldown: "10m"}
        output: {severity: low, confidence: low, risk_score: 1, tags: []}
        """,
        encoding="utf-8",
    )

    rules = load_rules(tmp_path)
    assert [r.id for r in rules] == ["R1"]

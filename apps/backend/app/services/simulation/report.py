"""Detection-coverage report: turns a simulation run into a demoable artifact.

Answers two questions in one document: which rules actually fired against a
live backend just now (`RuleCoverage`, built from `SimulationRunner.check_fired()`),
and which ATT&CK techniques this detection suite doesn't attempt to cover at
all (`uncovered_techniques`, from `mitre_reference.TECHNIQUES`) — the
"vulnerability management" framing Feature 1 is meant to demonstrate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.domain.rules.rule_schema import Rule
from app.services.simulation.mitre_reference import TECHNIQUES


@dataclass
class RuleCoverage:
    rule_id: str
    rule_name: str
    severity: str
    technique_id: str | None
    technique: str | None
    tactic: str | None
    fired: bool


@dataclass
class CoverageReport:
    generated_at: datetime
    rule_coverage: list[RuleCoverage]
    uncovered_techniques: list[dict[str, str]]

    @classmethod
    def build(cls, rules: list[Rule], fired: dict[str, bool]) -> CoverageReport:
        rule_coverage = [
            RuleCoverage(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.output.severity,
                technique_id=rule.output.mitre.technique_id if rule.output.mitre else None,
                technique=rule.output.mitre.technique if rule.output.mitre else None,
                tactic=rule.output.mitre.tactic if rule.output.mitre else None,
                fired=fired.get(rule.id, False),
            )
            for rule in rules
        ]
        uncovered_techniques = [
            {"technique_id": technique_id, **info}
            for technique_id, info in sorted(TECHNIQUES.items())
            if info["covered_by"] is None
        ]
        return cls(
            generated_at=datetime.now(timezone.utc),
            rule_coverage=rule_coverage,
            uncovered_techniques=uncovered_techniques,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "rules": [
                {
                    "rule_id": rc.rule_id,
                    "rule_name": rc.rule_name,
                    "severity": rc.severity,
                    "technique_id": rc.technique_id,
                    "technique": rc.technique,
                    "tactic": rc.tactic,
                    "fired": rc.fired,
                }
                for rc in self.rule_coverage
            ],
            "uncovered_techniques": self.uncovered_techniques,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        fired_count = sum(1 for rc in self.rule_coverage if rc.fired)
        total = len(self.rule_coverage)

        lines = [
            "# Detection Coverage Report",
            "",
            f"Generated: {self.generated_at.isoformat()}",
            "",
            f"**{fired_count}/{total} rules fired** during this simulation run.",
            "",
            "## Rules exercised",
            "",
            "| Rule ID | Name | Severity | ATT&CK Technique | Fired? |",
            "| --- | --- | --- | --- | --- |",
        ]
        for rc in self.rule_coverage:
            technique = f"{rc.technique_id} ({rc.technique})" if rc.technique_id else "-"
            fired_mark = "yes" if rc.fired else "no"
            lines.append(
                f"| {rc.rule_id} | {rc.rule_name} | {rc.severity} | {technique} | {fired_mark} |"
            )

        lines += [
            "",
            "## Known gaps (ATT&CK techniques not covered by any rule)",
            "",
            "| Technique | Name | Tactic |",
            "| --- | --- | --- |",
        ]
        for t in self.uncovered_techniques:
            lines.append(f"| {t['technique_id']} | {t['technique']} | {t['tactic']} |")
        lines.append("")

        return "\n".join(lines)

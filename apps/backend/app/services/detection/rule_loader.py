from pathlib import Path
from typing import Any

import yaml
from app.domain.rules.rule_schema import Rule


class RuleLoadError(Exception):
    pass


def load_rule_file(path: Path) -> Rule:
    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuleLoadError(f"YAML parse failed: {path.name}: {e}") from e

    try:
        return Rule.model_validate(data)
    except Exception as e:
        raise RuleLoadError(f"Rule validation failed: {path.name}: {e}") from e


def load_rules(rules_dir: Path) -> list[Rule]:
    rules: list[Rule] = []
    for p in sorted(rules_dir.glob("*.yml")):
        r = load_rule_file(p)
        if r.enabled:
            rules.append(r)
    return rules

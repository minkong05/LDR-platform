import os
import time
from pathlib import Path

import httpx
from app.services.detection.rule_loader import load_rules
from app.services.simulation.attack_shapes import build_events_for_rule
from app.settings import settings


class SimulationRunner:
    def __init__(self):
        if settings.ENV == "production":
            raise RuntimeError("SimulationRunner refuses to run with settings.ENV=production")

        self.base_url = os.getenv("SIMULATION_BASE_URL", "http://localhost:8000")
        self.agent_token = settings.AGENT_TOKEN
        self.rules_dir = Path(os.getenv("RULES_DIR", "rules"))
        self.rules = load_rules(self.rules_dir)

    def send_attacks(self, rule_ids: list[str] | None = None) -> list[str]:
        rules = [r for r in self.rules if rule_ids is None or r.id in rule_ids]
        attempted = []
        for rule in rules:
            payload = build_events_for_rule(rule)
            response = httpx.post(
                f"{self.base_url}/v1/ingest/events",
                json={"events": payload},
                headers={"X-Agent-Token": self.agent_token},
                timeout=10,
            )
            response.raise_for_status()
            attempted.append(rule.id)
        return attempted

    def wait_for_detection(self, seconds: int):
        time.sleep(seconds)

    def check_fired(self, rule_ids: list[str]) -> dict[str, bool]:
        # GET /v1/alerts has no auth today (closed by Feature 2b, which will
        # need X-Dashboard-Token instead) — no header required yet.
        response = httpx.get(
            f"{self.base_url}/v1/alerts",
            params={"limit": 200},
            timeout=10,
        )
        response.raise_for_status()
        alerts = response.json()["items"]
        fired_rule_ids = {a["rule_id"] for a in alerts}
        return {rule_id: rule_id in fired_rule_ids for rule_id in rule_ids}

    def build_report(self):
        pass

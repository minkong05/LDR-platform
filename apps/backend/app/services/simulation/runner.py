import os
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

    def attack(self):
        for rule in self.rules:
            payload = build_events_for_rule(rule)
            response = httpx.post(
                f"{self.base_url}/v1/ingest/events",
                json={"events": payload},
                headers={"X-Agent-Token": self.agent_token},
                timeout=10,
            )
            response.raise_for_status()

    def report(self):
        pass

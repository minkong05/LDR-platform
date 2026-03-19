from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.domain.rules.rule_schema import Rule
from app.domain.schemas.alert import Alert
from app.services.detection.match import get_by_dotted_path, rule_matches
from app.services.detection.timeparse import parse_duration


@dataclass
class CounterState:
    timestamps: list[datetime]
    last_alert_at: datetime | None = None


class ThresholdEngine:
    """
    In-memory threshold engine for MVP.

    Later:
    - Replace state with Redis or DB aggregation for durability
    - Write alerts to Postgres
    """

    def __init__(self, rules: list[Rule]):
        self.rules = rules
        # key: (rule_id, group_value_str)
        self.state: dict[tuple[str, str], CounterState] = {}

    def process(self, events: list[dict[str, Any]]) -> list[Alert]:
        alerts: list[Alert] = []
        # ensure stable order by timestamp
        events_sorted = sorted(events, key=lambda e: e.get("@timestamp", ""))

        for ev in events_sorted:
            ts = self._parse_ts(ev.get("@timestamp"))
            if ts is None:
                continue

            for rule in self.rules:
                if not rule_matches(ev, rule.match):
                    continue

                group_key = self._group_key(rule, ev)
                if group_key is None:
                    continue

                win = parse_duration(rule.condition.window)
                cooldown = (
                    parse_duration(rule.condition.cooldown)
                    if rule.condition.cooldown
                    else timedelta(0)
                )

                key = (rule.id, group_key)
                st = self.state.setdefault(key, CounterState(timestamps=[]))

                # Cleanup old timestamps (sliding window)
                st.timestamps = [t for t in st.timestamps if (ts - t) <= win]
                st.timestamps.append(ts)

                # Cooldown check
                if st.last_alert_at is not None and (ts - st.last_alert_at) < cooldown:
                    continue

                if len(st.timestamps) >= rule.condition.count:
                    alert = Alert(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.output.severity,
                        confidence=rule.output.confidence,
                        risk_score=rule.output.risk_score,
                        source_ip=group_key,
                        started_at=min(st.timestamps),
                        ended_at=max(st.timestamps),
                        event_count=len(st.timestamps),
                        sample_event_ids=[],
                    )
                    alerts.append(alert)
                    st.last_alert_at = ts

        return alerts

    def _group_key(self, rule: Rule, ev: dict[str, Any]) -> str | None:
        # MVP supports only one group field, typically "source.ip"
        fields = rule.condition.group_by
        if len(fields) != 1:
            return None
        v = get_by_dotted_path(ev, fields[0])
        return str(v) if v is not None else None

    def _parse_ts(self, s: Any) -> datetime | None:
        if not s:
            return None
        try:
            # handles "2026-02-21T20:00:00+00:00" style
            dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

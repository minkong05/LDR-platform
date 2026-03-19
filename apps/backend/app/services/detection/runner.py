from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.db.models.alert import Alert as AlertRow
from app.db.models.event import Event
from app.domain.rules.rule_schema import Rule
from app.services.detection.engine import ThresholdEngine
from app.services.detection.rule_loader import load_rules
from sqlalchemy import select
from sqlalchemy.orm import Session


def _event_to_detection_dict(e: Event) -> dict[str, Any]:
    """
    Detection engine operates on normalized dicts.
    Ensure required fields exist.
    """
    if not e.normalized:
        return {}
    return e.normalized


def run_detection_once(
    db: Session,
    *,
    rules_dir: Path,
    lookback_minutes: int = 30,
) -> int:
    """
    Load rules and evaluate events from the last lookback window.
    Write alerts to DB.
    Returns number of alerts inserted.
    """
    rules: list[Rule] = load_rules(rules_dir)
    engine = ThresholdEngine(rules)

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)

    rows = (
        db.execute(
            select(Event)
            .where(Event.event_timestamp >= cutoff)
            .where(Event.normalized.is_not(None))
        )
        .scalars()
        .all()
    )

    events = [_event_to_detection_dict(r) for r in rows]
    events = [e for e in events if e]  # drop empty

    alerts = engine.process(events)

    inserted = 0
    for a in alerts:
        # Simple dedupe rule:
        #  don't create duplicate open alerts for same rule+ip within same ended_at minute.
        existing = (
            db.execute(
                select(AlertRow).where(
                    AlertRow.rule_id == a.rule_id,
                    AlertRow.source_ip == a.source_ip,
                    AlertRow.status.in_(["open", "triaged"]),
                    AlertRow.ended_at >= (a.ended_at - timedelta(minutes=10)),
                )
            )
            .scalars()
            .first()
        )

        if existing:
            continue

        row = AlertRow(
            rule_id=a.rule_id,
            rule_name=a.rule_name,
            severity=a.severity,
            confidence=a.confidence,
            risk_score=a.risk_score,
            source_ip=a.source_ip,
            started_at=a.started_at,
            ended_at=a.ended_at,
            event_count=a.event_count,
            status="open",
            context={},
        )
        db.add(row)
        db.commit()
        inserted += 1

    return inserted

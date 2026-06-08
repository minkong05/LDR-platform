# apps/backend/app/services/risk/scorer.py

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 40.0,
    "high": 20.0,
    "medium": 8.0,
    "low": 3.0,
}

DECAY_LAMBDA = 0.02  # e^(-λ·h): ~40% decay at 24h, ~65% at 48h


def _decay(created_at: datetime, now: datetime) -> float:
    """Exponential time decay based on alert age in hours."""
    age_hours = max(0.0, (now - created_at).total_seconds() / 3600)
    return math.exp(-DECAY_LAMBDA * age_hours)


def compute_ip_risk_score(
    alerts: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    Compute a risk score for a single IP from its alert list.

    Each alert dict must have: severity, status, created_at (ISO string or datetime).
    Returns a dict with score, contributing_alerts count, and breakdown by severity.

    Only open and triaged alerts contribute — closed alerts are excluded.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    active_alerts = [a for a in alerts if a.get("status") in ("open", "triaged")]

    total = 0.0
    breakdown: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for alert in active_alerts:
        severity = alert.get("severity", "low")
        weight = SEVERITY_WEIGHTS.get(severity, 0.0)
        if weight == 0:
            continue

        raw_ts = alert.get("created_at")
        if isinstance(raw_ts, str):
            created_at = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        elif isinstance(raw_ts, datetime):
            created_at = raw_ts
        else:
            created_at = now  # fallback: no decay

        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        decay = _decay(created_at, now)
        total += weight * decay
        breakdown[severity] = breakdown.get(severity, 0) + 1

    score = min(100, round(total))

    return {
        "score": score,
        "contributing_alerts": len(active_alerts),
        "breakdown": breakdown,
        "label": _score_label(score),
    }


def _score_label(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    if score > 0:
        return "low"
    return "none"

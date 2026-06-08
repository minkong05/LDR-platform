# apps/backend/tests/unit/test_risk_scorer.py

import math
from datetime import datetime, timedelta, timezone

import pytest
from app.services.risk.scorer import DECAY_LAMBDA, _decay


def _now() -> datetime:
    return datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc)


def _alert(severity: str, status: str = "open", age_hours: float = 0.0) -> dict:
    ts = _now() - timedelta(hours=age_hours)
    return {
        "severity": severity,
        "status": status,
        "created_at": ts.isoformat(),
    }


# ── Decay function ─────────────────────────────────────────────────────────────


def test_decay_at_zero_hours_is_one():
    now = _now()
    assert _decay(now, now) == pytest.approx(1.0)


def test_decay_reduces_over_time():
    now = _now()
    old = now - timedelta(hours=24)
    d = _decay(old, now)
    assert d == pytest.approx(math.exp(-DECAY_LAMBDA * 24))
    assert d < 1.0
    assert d > 0.0

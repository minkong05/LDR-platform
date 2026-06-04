# 📄 apps/backend/tests/unit/test_evidence_builder.py

import io
import json
import zipfile
from datetime import datetime, timezone

from app.services.evidence.builder import _build_summary_md, build_evidence_zip


def _now() -> datetime:
    return datetime(2026, 5, 1, 14, 30, 0, tzinfo=timezone.utc)


def _sample_alert(rule_id: str = "LDR-WEB-001", severity: str = "high") -> dict:
    return {
        "id": "abc-123",
        "rule_id": rule_id,
        "rule_name": "Brute force login failures",
        "severity": severity,
        "status": "open",
        "event_count": 12,
        "source_ip": "1.2.3.4",
        "created_at": "2026-05-01T14:00:00+00:00",
        "risk_score": 70,
    }


def _sample_event(path: str = "/login") -> dict:
    return {
        "id": "ev-001",
        "source_ip": "1.2.3.4",
        "event_timestamp": "2026-05-01T14:00:00+00:00",
        "log_source": "flask",
        "normalized": {
            "url": {"path": path},
            "event": {"action": "login_failed"},
        },
    }


def _sample_risk() -> dict:
    return {
        "score": 42,
        "label": "high",
        "contributing_alerts": 1,
        "breakdown": {"critical": 0, "high": 1, "medium": 0, "low": 0},
    }


# ── ZIP structure ──────────────────────────────────────────────────────────────


def test_zip_contains_three_files():
    data = build_evidence_zip(
        ip="1.2.3.4",
        alerts=[_sample_alert()],
        events=[_sample_event()],
        risk=_sample_risk(),
        now=_now(),
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
    assert len(names) == 3
    assert any(n.endswith("summary.md") for n in names)
    assert any(n.endswith("alerts.json") for n in names)
    assert any(n.endswith("events.json") for n in names)


def test_zip_folder_name_contains_ip_and_timestamp():
    data = build_evidence_zip(
        ip="1.2.3.4",
        alerts=[],
        events=[],
        risk={
            "score": 0,
            "label": "none",
            "contributing_alerts": 0,
            "breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        },
        now=_now(),
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        folder = zf.namelist()[0].split("/")[0]
    assert "1_2_3_4" in folder
    assert "20260501" in folder


def test_alerts_json_is_valid_and_matches_input():
    alerts = [_sample_alert("LDR-WEB-001"), _sample_alert("LDR-WEB-002")]
    data = build_evidence_zip(
        ip="1.2.3.4",
        alerts=alerts,
        events=[],
        risk=_sample_risk(),
        now=_now(),
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        alerts_name = next(n for n in zf.namelist() if n.endswith("alerts.json"))
        parsed = json.loads(zf.read(alerts_name))
    assert len(parsed) == 2
    assert parsed[0]["rule_id"] == "LDR-WEB-001"
    assert parsed[1]["rule_id"] == "LDR-WEB-002"


def test_events_json_is_valid_and_matches_input():
    events = [_sample_event("/login"), _sample_event("/admin")]
    data = build_evidence_zip(
        ip="1.2.3.4",
        alerts=[],
        events=events,
        risk=_sample_risk(),
        now=_now(),
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        events_name = next(n for n in zf.namelist() if n.endswith("events.json"))
        parsed = json.loads(zf.read(events_name))
    assert len(parsed) == 2


def test_empty_bundle_still_produces_valid_zip():
    data = build_evidence_zip(
        ip="10.0.0.1",
        alerts=[],
        events=[],
        risk={
            "score": 0,
            "label": "none",
            "contributing_alerts": 0,
            "breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        },
        now=_now(),
    )
    assert zipfile.is_zipfile(io.BytesIO(data))


# ── summary.md content ─────────────────────────────────────────────────────────


def test_summary_contains_ip():
    md = _build_summary_md(
        ip="1.2.3.4",
        generated_at=_now(),
        time_range_start=None,
        time_range_end=None,
        risk=_sample_risk(),
        alerts=[_sample_alert()],
        events=[_sample_event()],
    )
    assert "1.2.3.4" in md


def test_summary_contains_risk_score():
    md = _build_summary_md(
        ip="1.2.3.4",
        generated_at=_now(),
        time_range_start=None,
        time_range_end=None,
        risk=_sample_risk(),
        alerts=[],
        events=[],
    )
    assert "42/100" in md
    assert "HIGH" in md


def test_summary_contains_alert_table_row():
    md = _build_summary_md(
        ip="1.2.3.4",
        generated_at=_now(),
        time_range_start=None,
        time_range_end=None,
        risk=_sample_risk(),
        alerts=[_sample_alert("LDR-WEB-001", "high")],
        events=[],
    )
    assert "LDR-WEB-001" in md
    assert "HIGH" in md


def test_summary_contains_top_paths():
    events = [_sample_event("/login")] * 5 + [_sample_event("/admin")] * 2
    md = _build_summary_md(
        ip="1.2.3.4",
        generated_at=_now(),
        time_range_start=None,
        time_range_end=None,
        risk=_sample_risk(),
        alerts=[],
        events=events,
    )
    assert "/login" in md
    assert "/admin" in md


def test_summary_shows_all_time_when_no_range():
    md = _build_summary_md(
        ip="1.2.3.4",
        generated_at=_now(),
        time_range_start=None,
        time_range_end=None,
        risk=_sample_risk(),
        alerts=[],
        events=[],
    )
    assert "all time" in md


def test_summary_shows_time_range_when_provided():
    from datetime import timedelta

    start = _now() - timedelta(hours=24)
    end = _now()
    md = _build_summary_md(
        ip="1.2.3.4",
        generated_at=_now(),
        time_range_start=start,
        time_range_end=end,
        risk=_sample_risk(),
        alerts=[],
        events=[],
    )
    assert "2026-04-30" in md
    assert "2026-05-01" in md

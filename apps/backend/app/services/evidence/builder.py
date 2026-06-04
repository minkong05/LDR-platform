# 📄 apps/backend/app/services/evidence/builder.py

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any


def _json_bytes(data: Any) -> bytes:
    """Serialize to indented JSON bytes."""
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def _build_summary_md(
    *,
    ip: str,
    generated_at: datetime,
    time_range_start: datetime | None,
    time_range_end: datetime | None,
    risk: dict[str, Any],
    alerts: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> str:
    """
    Produce a markdown summary that reads like an analyst handoff note.
    Plain prose + tables — no raw JSON in this file.
    """
    lines: list[str] = []

    def h(level: int, text: str) -> None:
        lines.append(f"{'#' * level} {text}\n")

    def p(text: str) -> None:
        lines.append(f"{text}\n")

    def blank() -> None:
        lines.append("")

    # ── Header ────────────────────────────────────────────────
    h(1, f"Evidence Bundle — {ip}")
    p(f"**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC")

    range_str = "all time"
    if time_range_start and time_range_end:
        range_str = (
            f"{time_range_start.strftime('%Y-%m-%d %H:%M')} → "
            f"{time_range_end.strftime('%Y-%m-%d %H:%M')} UTC"
        )
    elif time_range_start:
        range_str = f"from {time_range_start.strftime('%Y-%m-%d %H:%M')} UTC"
    elif time_range_end:
        range_str = f"until {time_range_end.strftime('%Y-%m-%d %H:%M')} UTC"

    p(f"**Time range:** {range_str}")
    p(f"**Source IP:** `{ip}`")
    blank()

    # ── Risk summary ──────────────────────────────────────────
    h(2, "Risk Assessment")
    score = risk.get("score", 0)
    label = risk.get("label", "none").upper()
    contributing = risk.get("contributing_alerts", 0)
    p(f"**Risk score:** {score}/100 ({label})")
    p(f"**Contributing alerts:** {contributing} open or triaged")

    breakdown = risk.get("breakdown", {})
    if any(breakdown.values()):
        blank()
        p("| Severity | Count |")
        p("|----------|-------|")
        for sev in ("critical", "high", "medium", "low"):
            count = breakdown.get(sev, 0)
            if count:
                p(f"| {sev.capitalize()} | {count} |")
    blank()

    # ── Alert summary ─────────────────────────────────────────
    h(2, "Alerts")
    if not alerts:
        p("No alerts found for this IP in the selected time range.")
    else:
        p(f"{len(alerts)} alert(s) recorded.")
        blank()
        p("| Rule ID | Rule Name | Severity | Status | Events | Detected |")
        p("|---------|-----------|----------|--------|--------|----------|")
        for a in alerts:
            detected = str(a.get("created_at", ""))[:19].replace("T", " ")
            p(
                f"| {a.get('rule_id', '')} "
                f"| {a.get('rule_name', '')} "
                f"| {a.get('severity', '').upper()} "
                f"| {a.get('status', '').upper()} "
                f"| {a.get('event_count', '')} "
                f"| {detected} |"
            )
    blank()

    # ── Event summary ─────────────────────────────────────────
    h(2, "Events")
    if not events:
        p("No events found for this IP in the selected time range.")
    else:
        p(f"{len(events)} event(s) recorded.")

        # Top paths breakdown
        path_counts: dict[str, int] = {}
        for ev in events:
            norm = ev.get("normalized") or {}
            url = norm.get("url") or {}
            path = url.get("path")
            if path:
                path_counts[path] = path_counts.get(path, 0) + 1

        if path_counts:
            blank()
            p("**Top requested paths:**")
            blank()
            p("| Path | Count |")
            p("|------|-------|")
            for path, count in sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                p(f"| `{path}` | {count} |")
    blank()

    # ── Analyst notes placeholder ─────────────────────────────
    h(2, "Analyst Notes")
    p("_Add investigation notes here._")
    blank()

    # ── Files in this bundle ──────────────────────────────────
    h(2, "Files")
    p("| File | Contents |")
    p("|------|----------|")
    p("| `alerts.json` | Full alert records for this IP |")
    p("| `events.json` | Full event records for this IP |")
    p("| `summary.md` | This file |")
    blank()

    return "\n".join(lines)


def build_evidence_zip(
    *,
    ip: str,
    alerts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    risk: dict[str, Any],
    time_range_start: datetime | None = None,
    time_range_end: datetime | None = None,
    now: datetime | None = None,
) -> bytes:
    """
    Build an in-memory ZIP bundle and return the raw bytes.

    The ZIP contains:
      evidence_<ip>_<timestamp>/
        summary.md
        alerts.json
        events.json
    """
    if now is None:
        now = datetime.now(timezone.utc)

    ts_slug = now.strftime("%Y%m%d_%H%M%S")
    # Sanitize IP for use in filename (replace dots and colons)
    ip_slug = ip.replace(".", "_").replace(":", "_")
    folder = f"evidence_{ip_slug}_{ts_slug}"

    summary_md = _build_summary_md(
        ip=ip,
        generated_at=now,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        risk=risk,
        alerts=alerts,
        events=events,
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{folder}/summary.md", summary_md.encode("utf-8"))
        zf.writestr(f"{folder}/alerts.json", _json_bytes(alerts))
        zf.writestr(f"{folder}/events.json", _json_bytes(events))

    return buf.getvalue()

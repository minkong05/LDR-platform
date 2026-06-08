# 📄 apps/backend/app/routers/entities.py

import io
from datetime import datetime, timezone
from typing import Annotated

from app.db.models.alert import Alert
from app.db.models.event import Event
from app.deps import get_db
from app.schemas.alerts import AlertOut
from app.schemas.entities import IPRiskOut, IPSummaryOut, SeverityBreakdown, TopItem
from app.schemas.events import EventOut
from app.services.evidence.builder import build_evidence_zip
from app.services.risk.scorer import compute_ip_risk_score
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

router = APIRouter(tags=["entities"])


@router.get("/entities/ip/{ip}", response_model=IPSummaryOut)
def ip_summary(
    ip: str,
    db: Session = Depends(get_db),  # noqa: B008
):
    base = select(Event).where(Event.source_ip == ip)

    total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()

    first_seen = db.execute(
        select(func.min(Event.event_timestamp)).where(Event.source_ip == ip)
    ).scalar_one()

    last_seen = db.execute(
        select(func.max(Event.event_timestamp)).where(Event.source_ip == ip)
    ).scalar_one()

    path_expr = Event.normalized["url"]["path"].astext
    top_paths_rows = db.execute(
        select(path_expr, func.count())
        .where(Event.source_ip == ip)
        .where(Event.normalized.is_not(None))
        .where(path_expr.is_not(None))
        .group_by(path_expr)
        .order_by(func.count().desc())
        .limit(10)
    ).all()

    status_expr = Event.normalized["http"]["response"]["status_code"].astext
    status_rows = db.execute(
        select(status_expr, func.count())
        .where(Event.source_ip == ip)
        .where(Event.normalized.is_not(None))
        .where(status_expr.is_not(None))
        .group_by(status_expr)
        .order_by(func.count().desc())
        .limit(10)
    ).all()

    top_paths = [TopItem(key=str(k), count=int(c)) for k, c in top_paths_rows]
    status_codes = [TopItem(key=str(k), count=int(c)) for k, c in status_rows]

    return IPSummaryOut(
        ip=ip,
        first_seen=first_seen,
        last_seen=last_seen,
        total_events=int(total),
        top_paths=top_paths,
        status_codes=status_codes,
    )


@router.get("/entities/ip/{ip}/risk", response_model=IPRiskOut)
def ip_risk(
    ip: str,
    db: Session = Depends(get_db),  # noqa: B008
):
    rows = db.execute(
        select(Alert.severity, Alert.status, Alert.created_at).where(Alert.source_ip == ip)
    ).all()

    alerts_for_scorer = [
        {
            "severity": row.severity,
            "status": row.status,
            "created_at": row.created_at,
        }
        for row in rows
    ]

    result = compute_ip_risk_score(alerts_for_scorer, now=datetime.now(timezone.utc))

    return IPRiskOut(
        ip=ip,
        score=result["score"],
        label=result["label"],
        contributing_alerts=result["contributing_alerts"],
        breakdown=SeverityBreakdown(**result["breakdown"]),
    )


@router.get("/entities/ip/{ip}/evidence")
def ip_evidence(
    ip: str,
    db: Session = Depends(get_db),  # noqa: B008
    start: Annotated[
        datetime | None,
        Query(description="Start of time range (ISO8601 UTC)"),
    ] = None,
    end: Annotated[
        datetime | None,
        Query(description="End of time range (ISO8601 UTC)"),
    ] = None,
):
    """
    Export a ZIP evidence bundle for an IP.
    Contains summary.md, alerts.json, and events.json.
    Optionally scoped to a time range via ?start= and ?end=.
    """
    # ── Query alerts ──────────────────────────────────────────
    alert_stmt = select(Alert).where(Alert.source_ip == ip).order_by(desc(Alert.created_at))
    if start:
        alert_stmt = alert_stmt.where(Alert.created_at >= start)
    if end:
        alert_stmt = alert_stmt.where(Alert.created_at <= end)

    alert_rows = db.execute(alert_stmt).scalars().all()
    alerts_data = [
        AlertOut.model_validate(r, from_attributes=True).model_dump(mode="json") for r in alert_rows
    ]

    # ── Query events ──────────────────────────────────────────
    event_stmt = select(Event).where(Event.source_ip == ip).order_by(desc(Event.event_timestamp))
    if start:
        event_stmt = event_stmt.where(Event.event_timestamp >= start)
    if end:
        event_stmt = event_stmt.where(Event.event_timestamp <= end)

    event_rows = db.execute(event_stmt).scalars().all()
    events_data = [
        EventOut.model_validate(r, from_attributes=True).model_dump(mode="json") for r in event_rows
    ]

    # ── Compute risk (always current, not range-scoped) ───────
    all_alert_rows = db.execute(
        select(Alert.severity, Alert.status, Alert.created_at).where(Alert.source_ip == ip)
    ).all()
    risk_result = compute_ip_risk_score(
        [
            {
                "severity": r.severity,
                "status": r.status,
                "created_at": r.created_at,
            }
            for r in all_alert_rows
        ],
        now=datetime.now(timezone.utc),
    )

    # ── Build ZIP ─────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    zip_bytes = build_evidence_zip(
        ip=ip,
        alerts=alerts_data,
        events=events_data,
        risk=risk_result,
        time_range_start=start,
        time_range_end=end,
        now=now,
    )

    # ── Stream as file download ───────────────────────────────
    ip_slug = ip.replace(".", "_").replace(":", "_")
    ts_slug = now.strftime("%Y%m%d_%H%M%S")
    filename = f"evidence_{ip_slug}_{ts_slug}.zip"

    return StreamingResponse(
        io.BytesIO(zip_bytes),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

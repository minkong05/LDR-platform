# 📄 apps/backend/app/routers/entities.py

from datetime import datetime, timezone

from app.db.models.alert import Alert
from app.db.models.event import Event
from app.deps import get_db
from app.schemas.entities import IPRiskOut, IPSummaryOut, SeverityBreakdown, TopItem
from app.services.risk.scorer import compute_ip_risk_score
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

router = APIRouter(tags=["entities"])


@router.get("/entities/ip/{ip}", response_model=IPSummaryOut)
def ip_summary(
    ip: str,
    db: Session = Depends(get_db),  # noqa: B008
):
    # Base query for this IP
    base = select(Event).where(Event.source_ip == ip)

    total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()

    first_seen = db.execute(
        select(func.min(Event.event_timestamp)).where(Event.source_ip == ip)
    ).scalar_one()

    last_seen = db.execute(
        select(func.max(Event.event_timestamp)).where(Event.source_ip == ip)
    ).scalar_one()

    # Top paths (from normalized.url.path if present)
    # We stored normalized as JSONB, so we can query it.
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

    # Status codes (normalized.http.response.status_code)
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
    """
    Compute a live risk score for an IP based on its open/triaged alerts.
    Closed alerts are excluded — triaging an alert reduces the score.
    """
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

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from app.auth.dashboard import require_dashboard_token
from app.db.models.alert import Alert
from app.db.models.event import Event
from app.deps import get_db
from app.schemas.alerts import AlertOut, AlertsListOut, AlertUpdateIn
from app.schemas.events import EventOut
from app.services.risk.scorer import compute_ip_risk_score
from app.services.summarization.service import SummarizationService
from app.settings import settings
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

router = APIRouter(tags=["alerts"])

# Cap on events pulled into the LLM prompt — keeps the prompt bounded even
# if an IP generated far more traffic than the rule's own event_count
# during the alert's detection window.
_MAX_SUMMARY_EVENTS = 50


@router.get("/alerts", response_model=AlertsListOut)
def list_alerts(
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_dashboard_token),
    status: Annotated[str | None, Query(description="open|triaged|closed")] = None,
    severity: Annotated[str | None, Query(description="low|medium|high|critical")] = None,
    source_ip: Annotated[str | None, Query(description="Filter by source IP")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = select(Alert)

    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if source_ip:
        stmt = stmt.where(Alert.source_ip == source_ip)

    stmt = stmt.order_by(desc(Alert.created_at)).limit(limit).offset(offset)
    rows = db.execute(stmt).scalars().all()
    items = [AlertOut.model_validate(r, from_attributes=True) for r in rows]
    return AlertsListOut(items=items, limit=limit, offset=offset)


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: UUID,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_dashboard_token),
):
    row = db.get(Alert, alert_id)
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertOut.model_validate(row, from_attributes=True)


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: UUID,
    patch: AlertUpdateIn,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_dashboard_token),
):
    row = db.get(Alert, alert_id)
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    row.status = patch.status
    row.closure_reason = patch.closure_reason
    row.notes = patch.notes
    db.commit()
    db.refresh(row)
    return AlertOut.model_validate(row, from_attributes=True)


@router.post("/alerts/{alert_id}/summary", response_model=AlertOut)
def generate_alert_summary(
    alert_id: UUID,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_dashboard_token),
):
    """
    Generate (once) and persist an LLM summary for an alert.

    Called on-demand when the dashboard's "Generate Summary" button is
    clicked — never eagerly on page load. If `row.summary` is already set,
    this is a no-op that just returns the alert as-is (no repeat LLM call).
    If LLM summarization is disabled or the call fails, `row.summary` stays
    None and the alert is returned unchanged — never an error response.
    """
    row = db.get(Alert, alert_id)
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    if row.summary is None and settings.llm_enabled:
        alert = AlertOut.model_validate(row, from_attributes=True).model_dump(mode="json")

        event_rows = (
            db.execute(
                select(Event)
                .where(Event.source_ip == row.source_ip)
                .where(Event.event_timestamp >= row.started_at)
                .where(Event.event_timestamp <= row.ended_at)
                .order_by(Event.event_timestamp)
                .limit(_MAX_SUMMARY_EVENTS)
            )
            .scalars()
            .all()
        )
        events = [
            EventOut.model_validate(e, from_attributes=True).model_dump(mode="json")
            for e in event_rows
        ]

        alert_rows = db.execute(
            select(Alert.severity, Alert.status, Alert.created_at).where(
                Alert.source_ip == row.source_ip
            )
        ).all()
        risk = compute_ip_risk_score(
            [
                {"severity": r.severity, "status": r.status, "created_at": r.created_at}
                for r in alert_rows
            ],
            now=datetime.now(timezone.utc),
        )

        summary_text = SummarizationService().summarize_alert(alert, events, risk)
        if summary_text is not None:
            row.summary = summary_text
            db.commit()
            db.refresh(row)

    return AlertOut.model_validate(row, from_attributes=True)

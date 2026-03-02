from typing import Annotated
from uuid import UUID

from app.db.models.alert import Alert
from app.deps import get_db
from app.schemas.alerts import AlertOut, AlertsListOut, AlertUpdateIn
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_model=AlertsListOut)
def list_alerts(
    db: Session = Depends(get_db),  # noqa: B008
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

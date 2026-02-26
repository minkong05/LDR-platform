from datetime import datetime
from typing import Annotated

from app.db.models.event import Event
from app.deps import get_db
from app.schemas.events import EventOut, EventsListOut
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

router = APIRouter(tags=["events"])


@router.get("/events", response_model=EventsListOut)
def list_events(
    db: Session = Depends(get_db),  # noqa: B008
    start: Annotated[datetime | None, Query(description="Start time (ISO8601 UTC)")] = None,
    end: Annotated[datetime | None, Query(description="End time (ISO8601 UTC)")] = None,
    source_ip: Annotated[str | None, Query(description="Filter by source IP")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    stmt = select(Event)

    if start is not None:
        stmt = stmt.where(Event.event_timestamp >= start)
    if end is not None:
        stmt = stmt.where(Event.event_timestamp <= end)
    if source_ip is not None:
        stmt = stmt.where(Event.source_ip == source_ip)

    stmt = stmt.order_by(desc(Event.event_timestamp)).limit(limit).offset(offset)

    rows = db.execute(stmt).scalars().all()
    # rows will be list[Event]

    items = [EventOut.model_validate(r, from_attributes=True) for r in rows]
    return EventsListOut(items=items, limit=limit, offset=offset)

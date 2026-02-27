from datetime import datetime, timedelta, timezone

from app.db.models.event import Event
from sqlalchemy import delete
from sqlalchemy.orm import Session


def delete_old_events(db: Session, retention_days: int) -> int:
    """
    Delete events older than retention_days based on event_timestamp.
    Returns number of deleted rows.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    stmt = delete(Event).where(Event.event_timestamp < cutoff)
    res = db.execute(stmt)
    db.commit()
    return int(res.rowcount or 0)

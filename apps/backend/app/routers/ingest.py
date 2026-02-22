from app.auth.agent import require_agent_token
from app.db.models.event import Event
from app.deps import get_db
from app.schemas.ingest import IngestBatch
from app.utils.dedupe import compute_dedupe_hash
from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

router = APIRouter(tags=["ingest"])


@router.post("/ingest/events")
def ingest_events(
    batch: IngestBatch,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_agent_token),
):
    inserted = 0
    deduped = 0

    for ev in batch.events:
        h = compute_dedupe_hash(
            log_source=ev.log_source,
            service_name=ev.service_name,
            source_ip=ev.source_ip,
            event_timestamp=ev.event_timestamp,
            raw=ev.raw,
        )

        row = Event(
            event_timestamp=ev.event_timestamp,
            log_source=ev.log_source,
            source_ip=ev.source_ip,
            raw={
                "service_name": ev.service_name,
                **ev.raw,
            },
            normalized=None,  # normalization comes next step
            dedupe_hash=h,
        )

        db.add(row)
        try:
            db.commit()
            inserted += 1
        except IntegrityError:
            db.rollback()
            deduped += 1

    return {"inserted": inserted, "deduped": deduped, "received": len(batch.events)}

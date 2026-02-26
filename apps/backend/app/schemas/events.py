from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class EventOut(BaseModel):
    id: UUID
    ingested_at: datetime
    event_timestamp: datetime
    log_source: str
    source_ip: str
    raw: dict[str, Any]
    normalized: dict[str, Any] | None
    dedupe_hash: str


class EventsListOut(BaseModel):
    items: list[EventOut]
    limit: int
    offset: int

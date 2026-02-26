from datetime import datetime

from pydantic import BaseModel


class TopItem(BaseModel):
    key: str
    count: int


class IPSummaryOut(BaseModel):
    ip: str
    first_seen: datetime | None
    last_seen: datetime | None
    total_events: int
    top_paths: list[TopItem]
    status_codes: list[TopItem]

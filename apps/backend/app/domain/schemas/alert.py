from datetime import datetime

from pydantic import BaseModel


class Alert(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    confidence: str
    risk_score: int
    source_ip: str

    started_at: datetime
    ended_at: datetime

    event_count: int
    sample_event_ids: list[str] = []

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class AlertOut(BaseModel):
    id: UUID
    created_at: datetime
    rule_id: str
    rule_name: str
    severity: str
    confidence: str
    risk_score: int
    source_ip: str
    started_at: datetime
    ended_at: datetime
    event_count: int
    status: str
    closure_reason: str | None
    notes: str | None
    context: dict


class AlertsListOut(BaseModel):
    items: list[AlertOut]
    limit: int
    offset: int


class AlertUpdateIn(BaseModel):
    status: str = Field(pattern="^(open|triaged|closed)$")
    closure_reason: str | None = None
    notes: str | None = None

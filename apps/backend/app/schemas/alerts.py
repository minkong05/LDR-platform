from datetime import datetime
from uuid import UUID

from app.domain.rules.rule_schema import MitreMapping
from pydantic import BaseModel, Field, field_validator


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
    mitre: MitreMapping | None = None

    @field_validator("mitre", mode="before")
    @classmethod
    def _empty_mitre_to_none(cls, v: dict | None) -> dict | None:
        # older/ruleless alerts store `{}` in the JSONB column, not null
        return v or None


class AlertsListOut(BaseModel):
    items: list[AlertOut]
    limit: int
    offset: int


class AlertUpdateIn(BaseModel):
    status: str = Field(pattern="^(open|triaged|closed)$")
    closure_reason: str | None = None
    notes: str | None = None

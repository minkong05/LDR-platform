# 📄 apps/backend/app/schemas/entities.py

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


class SeverityBreakdown(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class IPRiskOut(BaseModel):
    ip: str
    score: int  # 0–100
    label: str  # none / low / medium / high / critical
    contributing_alerts: int  # open + triaged alert count
    breakdown: SeverityBreakdown  # counts per severity tier

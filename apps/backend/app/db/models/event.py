import uuid
from datetime import datetime, timezone

from app.db.base import Base
from sqlalchemy import DateTime, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column


class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # When the platform ingested this record
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Timestamp of the actual event
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    log_source: Mapped[str] = mapped_column(String(32), nullable=False)  # nginx/flask/docker
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)

    # Raw envelope and normalized ECS-like event
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False)
    normalized: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Stable dedupe hash (unique)
    dedupe_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("dedupe_hash", name="uq_events_dedupe_hash"),
        Index("ix_events_event_timestamp", "event_timestamp"),
        Index("ix_events_source_ip", "source_ip"),
    )

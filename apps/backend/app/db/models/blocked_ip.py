# 📄 apps/backend/app/db/models/blocked_ip.py

import uuid
from datetime import datetime, timezone

from app.db.base import Base
from sqlalchemy import Boolean, DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    ip: Mapped[str] = mapped_column(String(64), nullable=False)

    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # None = block never expires automatically
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # "analyst", "system", or a future username
    blocked_by: Mapped[str] = mapped_column(String(64), nullable=False, default="analyst")

    # Set to False on unblock — keeps the history row, just deactivates it
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index("ix_blocked_ips_ip", "ip"),
        Index("ix_blocked_ips_is_active", "is_active"),
        Index("ix_blocked_ips_expires_at", "expires_at"),
    )

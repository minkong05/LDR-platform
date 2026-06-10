# 📄 apps/backend/app/db/models/audit_log.py

import uuid
from datetime import datetime, timezone

from app.db.base import Base
from sqlalchemy import JSON, DateTime, Index, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # e.g. "block_ip", "unblock_ip", "email_sent"
    action: Mapped[str] = mapped_column(String(64), nullable=False)

    # Who triggered the action — "analyst", "system", or future RBAC username
    actor: Mapped[str] = mapped_column(String(64), nullable=False)

    # The IP being acted on (null for non-IP actions like "email_sent")
    target_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Freeform detail — store alert_id, rule_id, expiry, email recipient, etc.
    detail: Mapped[dict] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False, default=dict
    )

    __table_args__ = (
        Index("ix_audit_log_created_at", "created_at"),
        Index("ix_audit_log_action", "action"),
        Index("ix_audit_log_target_ip", "target_ip"),
    )

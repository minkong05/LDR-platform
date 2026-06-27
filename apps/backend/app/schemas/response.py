# 📄 apps/backend/app/schemas/response.py

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class BlockIn(BaseModel):
    """Request body for POST /v1/response/block."""

    ip: str = Field(min_length=1, max_length=64, description="IP address to block")
    reason: str | None = Field(default=None, max_length=512)
    ttl_minutes: int | None = Field(
        default=None,
        ge=1,
        le=10_080,  # max 7 days
        description="Block duration in minutes. Omit for indefinite block.",
    )
    actor: str = Field(default="analyst", max_length=64)

    @field_validator("ip")
    @classmethod
    def ip_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("ip must not be blank")
        return v.strip()


class UnblockIn(BaseModel):
    """Request body for POST /v1/response/unblock/{ip}."""

    reason: str | None = Field(default=None, max_length=512)
    actor: str = Field(default="analyst", max_length=64)


class BlockDetail(BaseModel):
    """Serialized view of a single BlockedIP row."""

    id: str
    ip: str
    blocked_at: str
    expires_at: str | None
    reason: str | None
    blocked_by: str
    is_active: bool


class BlockOut(BaseModel):
    """Response for block/unblock actions."""

    ip: str
    note: str  # "blocked" | "already_blocked" | "unblocked" | "not_blocked"
    block: BlockDetail | None = None
    unblocked_count: int | None = None


class BlockStatusOut(BaseModel):
    """Response for GET /v1/response/block-status/{ip}."""

    ip: str
    is_blocked: bool
    block: BlockDetail | None = None


class AuditLogOut(BaseModel):
    """Serialized view of a single audit_log row."""

    id: str
    action: str
    actor: str
    target_ip: str | None
    detail: dict
    created_at: str


class AuditLogListOut(BaseModel):
    """Paginated audit log response."""

    items: list[AuditLogOut]
    limit: int
    offset: int

# 📄 apps/backend/app/services/response/block.py

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.db.models.audit_log import AuditLog
from app.db.models.blocked_ip import BlockedIP
from sqlalchemy import select
from sqlalchemy.orm import Session


def _now() -> datetime:
    return datetime.now(timezone.utc)


class BlockService:
    """
    Manages IP block/unblock state and the audit trail for those actions.

    All public methods write to audit_log unconditionally so every
    response action is traceable, even no-ops (e.g. trying to block
    an already-blocked IP).
    """

    def __init__(self, db: Session) -> None:
        self._db = db

    # ── Public API ──────────────────────────────────────────────────────────

    def block_ip(
        self,
        ip: str,
        *,
        reason: str | None = None,
        ttl_minutes: int | None = None,
        actor: str = "analyst",
    ) -> dict[str, Any]:
        """
        Block an IP.

        If the IP is already actively blocked, returns the existing block
        record without creating a duplicate. Still writes an audit entry
        so the attempt is visible.

        Args:
            ip:          The IP address to block.
            reason:      Human-readable reason (stored on the block row).
            ttl_minutes: If set, block expires after this many minutes.
                         None means indefinite.
            actor:       Who triggered the action (default "analyst").

        Returns a dict describing the resulting block.
        """
        now = _now()
        existing = self._active_block(ip)

        if existing is not None:
            self._write_audit(
                action="block_ip_noop",
                actor=actor,
                target_ip=ip,
                detail={
                    "reason": "already_blocked",
                    "existing_block_id": str(existing.id),
                },
            )
            return self._block_to_dict(existing, note="already_blocked")

        expires_at = (now + timedelta(minutes=ttl_minutes)) if ttl_minutes else None

        block = BlockedIP(
            ip=ip,
            blocked_at=now,
            expires_at=expires_at,
            reason=reason,
            blocked_by=actor,
            is_active=True,
        )
        self._db.add(block)
        self._db.flush()  # populate block.id before audit write

        self._write_audit(
            action="block_ip",
            actor=actor,
            target_ip=ip,
            detail={
                "block_id": str(block.id),
                "reason": reason,
                "ttl_minutes": ttl_minutes,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )

        self._db.commit()
        return self._block_to_dict(block, note="blocked")

    def unblock_ip(
        self,
        ip: str,
        *,
        reason: str | None = None,
        actor: str = "analyst",
    ) -> dict[str, Any]:
        """
        Deactivate all active blocks for an IP.

        Sets is_active=False on every matching row (there should normally
        only be one, but this handles edge cases gracefully).

        Returns a summary of how many blocks were deactivated.
        """
        # unused now = _now()
        rows = self._all_active_blocks(ip)

        if not rows:
            self._write_audit(
                action="unblock_ip_noop",
                actor=actor,
                target_ip=ip,
                detail={"reason": "not_currently_blocked"},
            )
            self._db.commit()
            return {"ip": ip, "unblocked_count": 0, "note": "not_blocked"}

        block_ids = []
        for row in rows:
            row.is_active = False
            block_ids.append(str(row.id))

        self._write_audit(
            action="unblock_ip",
            actor=actor,
            target_ip=ip,
            detail={
                "block_ids": block_ids,
                "reason": reason,
                "unblocked_count": len(rows),
            },
        )

        self._db.commit()
        return {"ip": ip, "unblocked_count": len(rows), "note": "unblocked"}

    def is_blocked(self, ip: str) -> bool:
        """
        Return True if the IP has an active, non-expired block.
        Does NOT write an audit entry — read-only check.
        """
        return self._active_block(ip) is not None

    def get_block_status(self, ip: str) -> dict[str, Any]:
        """
        Return full block status for an IP, suitable for API responses.
        Does NOT write an audit entry.
        """
        block = self._active_block(ip)
        if block is None:
            return {"ip": ip, "is_blocked": False, "block": None}
        return {"ip": ip, "is_blocked": True, "block": self._block_to_dict(block)}

    # ── Private helpers ─────────────────────────────────────────────────────

    def _active_block(self, ip: str) -> BlockedIP | None:
        """
        Return the first active, non-expired block for this IP, or None.

        A block is active when:
          - is_active = True
          - AND (expires_at IS NULL OR expires_at > now)
        """
        now = _now()
        stmt = (
            select(BlockedIP)
            .where(BlockedIP.ip == ip)
            .where(BlockedIP.is_active.is_(True))
            .where((BlockedIP.expires_at.is_(None)) | (BlockedIP.expires_at > now))
            .limit(1)
        )
        return self._db.execute(stmt).scalars().first()

    def _all_active_blocks(self, ip: str) -> list[BlockedIP]:
        """Return all active (possibly expired) blocks for bulk deactivation."""
        stmt = select(BlockedIP).where(BlockedIP.ip == ip).where(BlockedIP.is_active.is_(True))
        return list(self._db.execute(stmt).scalars().all())

    def _write_audit(
        self,
        *,
        action: str,
        actor: str,
        target_ip: str | None,
        detail: dict[str, Any],
    ) -> None:
        """Append a row to audit_log. Always called before commit."""
        entry = AuditLog(
            action=action,
            actor=actor,
            target_ip=target_ip,
            detail=detail,
        )
        self._db.add(entry)
        # No commit here — caller commits after all writes are done.

    @staticmethod
    def _block_to_dict(block: BlockedIP, note: str | None = None) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": str(block.id),
            "ip": block.ip,
            "blocked_at": block.blocked_at.isoformat(),
            "expires_at": block.expires_at.isoformat() if block.expires_at else None,
            "reason": block.reason,
            "blocked_by": block.blocked_by,
            "is_active": block.is_active,
        }
        if note:
            d["note"] = note
        return d

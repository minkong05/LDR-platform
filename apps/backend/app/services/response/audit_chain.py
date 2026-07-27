# 📄 apps/backend/app/services/response/audit_chain.py

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.db.models.audit_log import AuditLog
from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session


def canonical_json(
    id: uuid.UUID | str,
    created_at: datetime | str,
    action: str,
    actor: str,
    target_ip: str | None,
    detail: dict[str, Any],
) -> str:
    """
    Deterministic JSON serialization of the fields that make up one audit
    entry's hash input.

    `created_at` is normalized to tz-aware UTC first. SQLite has no native
    tz-aware datetime type, so a value written as UTC-aware comes back
    naive on read (same family of cross-dialect trap as the JSONB/SQLite
    issue in LEARNINGS.md §3) — without this, verify_chain() would report
    every entry as tampered on the SQLite test path even with zero tampering.
    """
    if isinstance(created_at, datetime) and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    payload = {
        "id": id,
        "created_at": created_at,
        "action": action,
        "actor": actor,
        "target_ip": target_ip,
        "detail": detail,
    }
    return json.dumps(payload, sort_keys=True, default=str)


def compute_entry_hash(
    prev_hash: str | None,
    *,
    id: uuid.UUID | str,
    created_at: datetime | str,
    action: str,
    actor: str,
    target_ip: str | None,
    detail: dict[str, Any],
) -> str:
    """sha256 hex digest chaining prev_hash onto this entry's canonical JSON."""
    payload = canonical_json(id, created_at, action, actor, target_ip, detail)
    digest_input = f"{prev_hash or ''}|{payload}".encode()
    return hashlib.sha256(digest_input).hexdigest()


def get_latest_hash(db: Session) -> str | None:
    """
    Return the entry_hash of the most recently chained row, or None if the
    chain hasn't started yet (fresh deploy, or every row so far predates
    this feature).

    Known race: this read and the caller's subsequent insert are not
    protected by a row lock, so two concurrent block/unblock calls could
    both read the same prev_hash and both chain onto it. Accepted as a
    demo-scale limitation — the real fix (`SELECT ... FOR UPDATE`) is
    Postgres-only and untestable on the SQLite unit-test path.
    """
    stmt = (
        select(AuditLog.entry_hash)
        .where(AuditLog.entry_hash.is_not(None))
        .order_by(desc(AuditLog.created_at))
        .limit(1)
    )
    return db.execute(stmt).scalars().first()


@dataclass(frozen=True)
class ChainVerificationResult:
    ok: bool
    checked: int
    first_invalid_id: str | None = None
    reason: str | None = None


def verify_chain(db: Session) -> ChainVerificationResult:
    """
    Walk audit_log in created_at order, recomputing each row's hash from
    its current field values and confirming it chains from the previous
    row's entry_hash.

    Leading rows with entry_hash IS NULL predate this feature (no backfill)
    and are treated as legacy: skipped rather than flagged. Verification
    starts at the first row with a non-null entry_hash, which must chain
    from prev_hash=None.

    Returns the first mismatch found, or ok=True if the whole chain (from
    that point on) is intact.
    """
    stmt = select(AuditLog).order_by(asc(AuditLog.created_at))
    rows = db.execute(stmt).scalars().all()

    expected_prev: str | None = None
    checked = 0
    started = False

    for row in rows:
        if not started:
            if row.entry_hash is None:
                continue
            started = True

        if row.prev_hash != expected_prev:
            return ChainVerificationResult(
                ok=False,
                checked=checked,
                first_invalid_id=str(row.id),
                reason="prev_hash_mismatch",
            )

        recomputed = compute_entry_hash(
            row.prev_hash,
            id=row.id,
            created_at=row.created_at,
            action=row.action,
            actor=row.actor,
            target_ip=row.target_ip,
            detail=row.detail,
        )
        if recomputed != row.entry_hash:
            return ChainVerificationResult(
                ok=False,
                checked=checked,
                first_invalid_id=str(row.id),
                reason="entry_hash_mismatch",
            )

        expected_prev = row.entry_hash
        checked += 1

    return ChainVerificationResult(ok=True, checked=checked)

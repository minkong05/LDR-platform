# 📄 apps/backend/tests/unit/test_audit_chain.py

from datetime import datetime, timedelta, timezone

import pytest
from app.db.base import Base
from app.db.models.audit_log import AuditLog
from app.services.response.audit_chain import (
    canonical_json,
    get_latest_hash,
    verify_chain,
)
from app.services.response.block import BlockService
from sqlalchemy import asc, create_engine, select
from sqlalchemy.orm import Session


@pytest.fixture()
def db():
    """In-memory SQLite session for audit chain tests."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def _ordered_rows(db) -> list[AuditLog]:
    return list(db.execute(select(AuditLog).order_by(asc(AuditLog.created_at))).scalars().all())


# ── canonical_json ────────────────────────────────────────────────────────


def test_canonical_json_normalizes_naive_datetime_to_utc():
    """
    SQLite roundtrips a tz-aware datetime as naive (see LEARNINGS.md §3 for
    the sibling JSONB/SQLite trap). canonical_json must produce the same
    string either way, or verify_chain would flag every entry as tampered
    on the SQLite test path even with zero tampering.
    """
    aware = canonical_json(
        id="abc",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        action="block_ip",
        actor="analyst",
        target_ip=None,
        detail={},
    )
    naive = canonical_json(
        id="abc",
        created_at=datetime(2026, 1, 1),
        action="block_ip",
        actor="analyst",
        target_ip=None,
        detail={},
    )
    assert aware == naive


# ── chain building via BlockService ──────────────────────────────────────


def test_get_latest_hash_none_when_empty(db):
    assert get_latest_hash(db) is None


def test_sequential_writes_chain_together(db):
    svc = BlockService(db)
    svc.block_ip("1.2.3.4", reason="brute force", actor="analyst")
    svc.unblock_ip("1.2.3.4", actor="analyst")
    svc.block_ip("5.6.7.8", actor="analyst")

    rows = _ordered_rows(db)
    assert len(rows) == 3

    assert rows[0].prev_hash is None
    assert all(row.entry_hash for row in rows)
    for prev_row, row in zip(rows, rows[1:], strict=False):
        assert row.prev_hash == prev_row.entry_hash

    assert get_latest_hash(db) == rows[-1].entry_hash


# ── verify_chain ──────────────────────────────────────────────────────────


def test_verify_chain_empty_log_is_ok(db):
    result = verify_chain(db)
    assert result.ok is True
    assert result.checked == 0
    assert result.first_invalid_id is None


def test_verify_chain_ok_for_untampered_log(db):
    svc = BlockService(db)
    svc.block_ip("1.2.3.4", actor="analyst")
    svc.unblock_ip("1.2.3.4", actor="analyst")
    svc.block_ip("5.6.7.8", reason="scan", ttl_minutes=30, actor="analyst")

    result = verify_chain(db)
    assert result.ok is True
    assert result.checked == 3
    assert result.first_invalid_id is None


def test_verify_chain_detects_tampered_detail(db):
    svc = BlockService(db)
    svc.block_ip("1.2.3.4", reason="brute force", actor="analyst")
    svc.unblock_ip("1.2.3.4", actor="analyst")
    svc.block_ip("5.6.7.8", actor="analyst")

    rows = _ordered_rows(db)
    tampered = rows[1]
    tampered.detail = {**tampered.detail, "reason": "attacker edited this after the fact"}
    db.commit()

    result = verify_chain(db)
    assert result.ok is False
    assert result.first_invalid_id == str(tampered.id)
    assert result.reason == "entry_hash_mismatch"
    assert result.checked == 1  # the untampered row before it verified cleanly


def test_verify_chain_detects_broken_prev_hash_link(db):
    svc = BlockService(db)
    svc.block_ip("1.2.3.4", actor="analyst")
    svc.block_ip("5.6.7.8", actor="analyst")

    rows = _ordered_rows(db)
    rows[1].prev_hash = "0" * 64
    db.commit()

    result = verify_chain(db)
    assert result.ok is False
    assert result.first_invalid_id == str(rows[1].id)
    assert result.reason == "prev_hash_mismatch"


def test_verify_chain_skips_legacy_null_hash_rows(db):
    """
    Rows written before this feature shipped have prev_hash=entry_hash=NULL
    (no backfill, by design). The verifier must treat those as legacy and
    start real verification from the first hashed row, not flag them.
    """
    legacy = AuditLog(
        action="block_ip",
        actor="analyst",
        target_ip="9.9.9.9",
        detail={"legacy": True},
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db.add(legacy)
    db.commit()

    svc = BlockService(db)
    svc.block_ip("1.2.3.4", actor="analyst")

    result = verify_chain(db)
    assert result.ok is True
    assert result.checked == 1  # only the new, hashed row is counted

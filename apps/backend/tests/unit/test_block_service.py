# 📄 apps/backend/tests/unit/test_block_service.py

from datetime import datetime, timedelta, timezone

import pytest
from app.db.base import Base
from app.db.models.audit_log import AuditLog
from app.db.models.blocked_ip import BlockedIP
from app.services.response.block import BlockService
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


@pytest.fixture()
def db():
    """In-memory SQLite session for block service tests."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


# ── block_ip ────────────────────────────────────────────────────────────────


def test_block_ip_creates_block_row(db):
    svc = BlockService(db)
    result = svc.block_ip("1.2.3.4", reason="brute force", actor="analyst")

    assert result["ip"] == "1.2.3.4"
    assert result["note"] == "blocked"
    assert result["is_active"] is True
    assert result["expires_at"] is None  # no TTL given


def test_block_ip_with_ttl_sets_expires_at(db):
    svc = BlockService(db)
    result = svc.block_ip("1.2.3.4", ttl_minutes=30, actor="analyst")

    assert result["expires_at"] is not None
    # expires_at should be roughly 30 minutes from now
    expires = datetime.fromisoformat(result["expires_at"])
    diff = expires - datetime.utcnow()  # both naive — SQLite strips tzinfo on roundtrip
    assert timedelta(minutes=28) < diff < timedelta(minutes=32)


def test_block_ip_duplicate_returns_noop(db):
    svc = BlockService(db)
    svc.block_ip("1.2.3.4", actor="analyst")
    result = svc.block_ip("1.2.3.4", actor="analyst")

    assert result["note"] == "already_blocked"
    # Only one block row should exist
    rows = db.execute(select(BlockedIP).where(BlockedIP.ip == "1.2.3.4")).scalars().all()
    assert len(rows) == 1


def test_block_ip_writes_audit_entry(db):
    svc = BlockService(db)
    svc.block_ip("2.3.4.5", reason="scanning", actor="analyst")

    entries = db.execute(select(AuditLog).where(AuditLog.target_ip == "2.3.4.5")).scalars().all()
    assert len(entries) == 1
    assert entries[0].action == "block_ip"
    assert entries[0].actor == "analyst"


def test_block_ip_noop_still_writes_audit(db):
    svc = BlockService(db)
    svc.block_ip("3.4.5.6", actor="analyst")
    svc.block_ip("3.4.5.6", actor="analyst")  # duplicate

    entries = db.execute(select(AuditLog).where(AuditLog.target_ip == "3.4.5.6")).scalars().all()
    assert len(entries) == 2
    actions = {e.action for e in entries}
    assert "block_ip" in actions
    assert "block_ip_noop" in actions


# ── unblock_ip ──────────────────────────────────────────────────────────────


def test_unblock_ip_deactivates_block(db):
    svc = BlockService(db)
    svc.block_ip("5.5.5.5", actor="analyst")
    result = svc.unblock_ip("5.5.5.5", actor="analyst")

    assert result["unblocked_count"] == 1
    assert result["note"] == "unblocked"
    assert svc.is_blocked("5.5.5.5") is False


def test_unblock_ip_not_blocked_returns_noop(db):
    svc = BlockService(db)
    result = svc.unblock_ip("9.9.9.9", actor="analyst")

    assert result["note"] == "not_blocked"
    assert result["unblocked_count"] == 0


def test_unblock_writes_audit_entry(db):
    svc = BlockService(db)
    svc.block_ip("6.6.6.6", actor="analyst")
    svc.unblock_ip("6.6.6.6", actor="analyst")

    entries = db.execute(select(AuditLog).where(AuditLog.target_ip == "6.6.6.6")).scalars().all()
    assert len(entries) == 2
    actions = {e.action for e in entries}
    assert "block_ip" in actions
    assert "unblock_ip" in actions


# ── is_blocked / get_block_status ───────────────────────────────────────────


def test_is_blocked_false_for_unknown_ip(db):
    assert BlockService(db).is_blocked("10.0.0.1") is False


def test_is_blocked_true_after_block(db):
    svc = BlockService(db)
    svc.block_ip("10.0.0.2", actor="analyst")
    assert svc.is_blocked("10.0.0.2") is True


def test_is_blocked_false_after_expired_ttl(db):
    """A block whose expires_at is in the past must not count as active."""
    svc = BlockService(db)
    # Directly insert an already-expired block row
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    block = BlockedIP(
        ip="10.0.0.3",
        blocked_at=past,
        expires_at=past,  # already expired
        is_active=True,
    )
    db.add(block)
    db.commit()

    assert svc.is_blocked("10.0.0.3") is False


def test_get_block_status_returns_full_detail(db):
    svc = BlockService(db)
    svc.block_ip("10.0.0.4", reason="test", ttl_minutes=60, actor="analyst")
    status = svc.get_block_status("10.0.0.4")

    assert status["is_blocked"] is True
    assert status["block"]["reason"] == "test"
    assert status["block"]["expires_at"] is not None

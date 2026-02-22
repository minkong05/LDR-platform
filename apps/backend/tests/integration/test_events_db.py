import os
from datetime import datetime, timezone

import pytest
from app.db.models.event import Event
from app.db.session import SessionLocal

pytestmark = pytest.mark.integration


def test_insert_event_roundtrip():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    db = SessionLocal()
    try:
        db.query(Event).delete()  # This is a Test DB, clear the data everytime i do the test
        db.commit()

        e = Event(
            event_timestamp=datetime.now(timezone.utc),
            log_source="nginx",
            source_ip="203.0.113.55",
            raw={"message": "test"},
            normalized=None,
            dedupe_hash="deadbeef" * 8,  # 64 chars
        )
        db.add(e)
        db.commit()

        fetched = db.query(Event).filter(Event.dedupe_hash == e.dedupe_hash).one()
        assert fetched.source_ip == "203.0.113.55"
        assert fetched.log_source == "nginx"
        assert fetched.raw["message"] == "test"
    finally:
        db.close()

import os
from datetime import datetime, timedelta, timezone

import pytest
from app.db.models.event import Event
from app.db.session import SessionLocal
from app.services.storage.retention import delete_old_events
from sqlalchemy import select

pytestmark = pytest.mark.integration


def test_retention_deletes_old_events():
    if os.getenv("RUN_INTEGRATION_TESTS") != "1":
        pytest.skip("Set RUN_INTEGRATION_TESTS=1 to run integration tests")

    db = SessionLocal()
    try:
        # Insert one old event + one recent event
        old_ts = datetime.now(timezone.utc) - timedelta(days=30)
        new_ts = datetime.now(timezone.utc)

        db.add(
            Event(
                event_timestamp=old_ts,
                log_source="nginx",
                source_ip="1.1.1.1",
                raw={"service_name": "demo-web", "msg": "old"},
                normalized={
                    "@timestamp": old_ts.isoformat(),
                    "log": {"source": "nginx"},
                    "event": {"kind": "event"},
                },
                dedupe_hash="a" * 64,
            )
        )
        db.add(
            Event(
                event_timestamp=new_ts,
                log_source="nginx",
                source_ip="2.2.2.2",
                raw={"service_name": "demo-web", "msg": "new"},
                normalized={
                    "@timestamp": new_ts.isoformat(),
                    "log": {"source": "nginx"},
                    "event": {"kind": "event"},
                },
                dedupe_hash="b" * 64,
            )
        )
        db.commit()

        deleted = delete_old_events(db, retention_days=14)
        assert deleted >= 1

        remaining = db.execute(select(Event)).scalars().all()
        assert len(remaining) == 1
        assert remaining[0].source_ip == "2.2.2.2"
    finally:
        db.close()

import os
import time
from pathlib import Path

import structlog

# Reuse backend code by importing from apps/backend via PYTHONPATH in container
from app.db.session import SessionLocal
from app.logging import configure_logging
from app.services.detection.runner import run_detection_once
from app.settings import settings

logger = structlog.get_logger()


def main() -> None:
    configure_logging(env=settings.ENV)

    interval = int(os.getenv("DETECTION_INTERVAL_SECONDS", "30"))
    lookback = int(os.getenv("DETECTION_LOOKBACK_MINUTES", "30"))
    rules_dir = Path(os.getenv("RULES_DIR", "rules"))

    logger.info(
        "worker_start",
        interval_seconds=interval,
        lookback_minutes=lookback,
        rules_dir=str(rules_dir),
    )

    while True:
        db = SessionLocal()
        try:
            inserted = run_detection_once(db, rules_dir=rules_dir, lookback_minutes=lookback)
            logger.info("detection_run", alerts_inserted=inserted)
        except Exception:
            logger.exception("detection_run_failed")
        finally:
            db.close()

        time.sleep(interval)


if __name__ == "__main__":
    main()

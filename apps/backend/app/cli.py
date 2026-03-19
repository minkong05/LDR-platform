import argparse
from pathlib import Path

from app.db.session import SessionLocal
from app.services.detection.runner import run_detection_once
from app.services.storage.retention import delete_old_events
from app.settings import settings


def main() -> None:
    parser = argparse.ArgumentParser(prog="ldr-cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ret = sub.add_parser("retention", help="Run retention cleanup")
    p_ret.add_argument("--days", type=int, default=settings.EVENT_RETENTION_DAYS)

    p_det = sub.add_parser("detect", help="Run detection once (load rules/*.yml and write alerts)")
    p_det.add_argument("--lookback-minutes", type=int, default=30)
    p_det.add_argument("--rules-dir", type=str, default="rules")

    args = parser.parse_args()

    db = SessionLocal()
    try:
        if args.cmd == "retention":
            deleted = delete_old_events(db, retention_days=args.days)
            print(f"deleted_events={deleted} retention_days={args.days}")

        elif args.cmd == "detect":
            inserted = run_detection_once(
                db,
                rules_dir=Path(args.rules_dir),
                lookback_minutes=args.lookback_minutes,
            )
            print(
                f"alerts_inserted={inserted} \
                    lookback_minutes={args.lookback_minutes} \
                    rules_dir={args.rules_dir}"
            )
    finally:
        db.close()


if __name__ == "__main__":
    main()

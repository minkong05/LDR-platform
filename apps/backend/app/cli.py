import argparse

from app.db.session import SessionLocal
from app.services.storage.retention import delete_old_events
from app.settings import settings


def main() -> None:
    parser = argparse.ArgumentParser(prog="ldr-cli")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("retention", help="Run retention cleanup")
    p.add_argument("--days", type=int, default=settings.EVENT_RETENTION_DAYS)

    # python -m ldr.cli retention --days 30

    args = parser.parse_args()

    if args.cmd == "retention":
        db = SessionLocal()
        try:
            deleted = delete_old_events(db, retention_days=args.days)
            print(f"deleted_events={deleted} retention_days={args.days}")
        finally:
            db.close()


if __name__ == "__main__":
    main()

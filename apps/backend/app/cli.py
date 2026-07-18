import argparse
from pathlib import Path

from app.db.session import SessionLocal
from app.services.detection.runner import run_detection_once
from app.services.simulation.runner import SimulationRunner
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

    p_sim = sub.add_parser(
        "simulate",
        help="Send synthetic attacks and write a detection-coverage report (local/demo only)",
    )
    p_sim.add_argument("--rules-dir", type=str, default="rules")
    p_sim.add_argument("--base-url", type=str, default="http://localhost:8000")
    p_sim.add_argument("--agent-token", type=str, default=None)
    p_sim.add_argument(
        "--wait-seconds",
        type=int,
        default=35,
        help="must exceed DETECTION_INTERVAL_SECONDS (default 30) or rules won't have fired yet",
    )
    p_sim.add_argument(
        "--rule-ids",
        type=str,
        default=None,
        help="comma-separated rule IDs to exercise (default: all enabled rules)",
    )
    p_sim.add_argument("--out", type=str, default="docs/detection-coverage.md")

    args = parser.parse_args()

    if args.cmd == "simulate":
        rule_ids = args.rule_ids.split(",") if args.rule_ids else None
        runner = SimulationRunner(
            rules_dir=Path(args.rules_dir),
            base_url=args.base_url,
            agent_token=args.agent_token,
        )
        attempted = runner.send_attacks(rule_ids=rule_ids)
        runner.wait_for_detection(args.wait_seconds)
        report = runner.build_report(rule_ids=attempted)

        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report.to_markdown())
        print(f"rules_attempted={len(attempted)} report_written={out_path}")
        return

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

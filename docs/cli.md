# CLI Reference (`app.cli`)

All commands are invoked as a module from the repo root, with the backend
package on `PYTHONPATH`:

```bash
PYTHONPATH=apps/backend python -m app.cli <command> [options]
```

Four subcommands are defined in `apps/backend/app/cli.py`: `retention`,
`detect`, `audit-verify`, `simulate`.

## `retention`

Deletes events older than N days (based on `event_timestamp`).

```bash
PYTHONPATH=apps/backend python -m app.cli retention --days 14
```

| Option | Default | Notes |
|---|---|---|
| `--days` | `EVENT_RETENTION_DAYS` from `.env` (14) | Events older than this many days are deleted |

Prints `deleted_events=<n> retention_days=<n>`.

Shortcut: `./scripts/retention.sh [days]` (also defaults to 14).

## `detect`

Runs one detection pass: loads YAML rules from `--rules-dir` and evaluates
them against events in the lookback window, writing any new alerts. This is
the same function (`run_detection_once`) the worker calls on every
`DETECTION_INTERVAL_SECONDS` tick — use this command to run it once, on
demand, without starting the worker loop.

```bash
PYTHONPATH=apps/backend python -m app.cli detect --lookback-minutes 30 --rules-dir rules
```

| Option | Default | Notes |
|---|---|---|
| `--lookback-minutes` | `30` | How far back to look for events |
| `--rules-dir` | `rules` | Directory of rule YAML files |

Prints `alerts_inserted=<n> lookback_minutes=<n> rules_dir=<path>`.

## `audit-verify`

Walks the `audit_log` hash chain (see `services/response/audit_chain.py`)
in `created_at` order and confirms each entry's hash matches its recorded
`prev_hash`. Rows written before the hash chain feature shipped have `NULL`
`prev_hash`/`entry_hash` and are treated as legacy — verification starts
from the first hashed row.

```bash
PYTHONPATH=apps/backend python -m app.cli audit-verify
```

No options. On success prints `OK entries_checked=<n>`. On failure prints
`TAMPERED entries_checked=<n> first_invalid_id=<id> reason=<reason>` and
exits with status 1.

The dashboard's "Verify integrity" button (admin-only, `response/audit.html`)
calls the same check via `GET /response/audit-log/verify`.

## `simulate`

Fires synthetic attacks at a **running** backend (one HTTP request per rule
via `/v1/ingest/events`), waits for the detection worker to evaluate them,
then checks `/v1/alerts` to see which rules fired and writes a
detection-coverage report. Local/demo only — refuses to run when
`settings.ENV == "production"`.

```bash
PYTHONPATH=apps/backend python -m app.cli simulate
```

Requires the stack to already be up (`./scripts/dev_up.sh`) since it talks
to a live backend, not the DB directly.

| Option | Default | Notes |
|---|---|---|
| `--rules-dir` | `rules` | Rule YAML files to build synthetic attacks from |
| `--base-url` | `http://localhost:8000` | Backend base URL |
| `--agent-token` | `settings.AGENT_TOKEN` | Sent as `X-Agent-Token` when posting synthetic events |
| `--dashboard-token` | `settings.DASHBOARD_API_TOKEN` | Sent as `X-Dashboard-Token` when reading back alerts |
| `--wait-seconds` | `35` | Must exceed `DETECTION_INTERVAL_SECONDS` (worker default 30s) or rules won't have fired yet when checked |
| `--rule-ids` | all enabled rules | Comma-separated rule IDs to exercise, e.g. `LDR-WEB-001,LDR-WEB-004` |
| `--out` | `docs/detection-coverage.md` | Where the markdown report is written |

Prints `rules_attempted=<n> report_written=<path>`.

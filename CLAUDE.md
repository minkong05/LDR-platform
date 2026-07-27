# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

LDR Platform is a self-built mini SOC (Security Operations Center): it ingests
web server logs (Flask, Nginx), normalizes them into an ECS-inspired schema,
runs YAML-based threshold detection rules against them, writes alerts, and
lets an analyst investigate and respond (block/unblock IPs) through a
dashboard with a full audit trail. v1.0.0 is feature-complete — see
`README.md` for the roadmap and `LEARNINGS.md` for design rationale and past
failure modes worth re-reading before touching detection, JSONB models, or
the response/audit path. A round of portfolio-driven additions on top of
v1.0.0 (MITRE ATT&CK mapping, attack simulation, dashboard/API auth,
LLM alert summarization, dashboard RBAC, audit hash chain) is tracked in
`FEATURE_PLAN.md`; only the VirusTotal IP-reputation feature there (3b) is
still unimplemented.

## Commands

```bash
# Start full stack (postgres, redis, backend, worker, dashboard) via Docker
./scripts/dev_up.sh
curl http://localhost:8000/v1/health   # backend health
open http://localhost:5001             # dashboard

# Seed synthetic events that trigger all detection rules
./scripts/trigger_all_rules.sh

# Unit tests (no external deps)
pytest -q

# Single test file / single test
pytest -q apps/backend/tests/unit/test_detection_engine.py
pytest -q apps/backend/tests/unit/test_detection_engine.py::test_name

# Integration tests (need Postgres; migrations run automatically via conftest)
docker compose up -d postgres
RUN_INTEGRATION_TESTS=1 pytest -q

# Both unit + integration
./scripts/test_all.sh

# Lint / format (must pass in CI — pinned via .pre-commit-config.yaml rev)
ruff check .
ruff format --check .   # add --fix / drop --check to actually fix

# Alembic migrations (run from apps/backend; DATABASE_URL from .env)
cd apps/backend && alembic upgrade head
cd apps/backend && alembic revision --autogenerate -m "message"

# Retention cleanup (deletes events older than N days)
./scripts/retention.sh 14

# Attack simulation + detection-coverage report (writes docs/detection-coverage.md)
PYTHONPATH=apps/backend python -m app.cli simulate

# Verify the audit log's tamper-evident hash chain
PYTHONPATH=apps/backend python -m app.cli audit-verify
```

CI (`.github/workflows/ci.yml`) runs on a real Postgres service container with
`RUN_INTEGRATION_TESTS=1` set for the whole job — ruff lint, ruff format
check, `alembic upgrade head`, then the full pytest suite (unit +
integration together, not separately).

Integration tests are marked `@pytest.mark.integration` and gated at fixture
level in `apps/backend/tests/conftest.py`: `apply_migrations_once` runs
`alembic upgrade head` against `DATABASE_URL` only when
`RUN_INTEGRATION_TESTS=1`, and the events/alerts tables are truncated before
every test function when that flag is set.

`pytest -q` from the repo root runs both `apps/backend/tests` and
`apps/dashboard/tests` in one pass — `testpaths`/`pythonpath` in
`pyproject.toml` cover both packages, so there's no separate dashboard test
command.

## Architecture

Three Python services under `apps/`, one shared package installed as `app`
(`apps/backend/app`, added to `pythonpath` in `pyproject.toml` so tests and
the worker can `import app.*` directly):

```
Agent → Ingest API → Normaliser → Event Store (Postgres) → Detection Worker
                                                                  ↓
                                                          Alert Writer → Email
                                                                  ↓
                                                       Investigation Dashboard
                                                                  ↓
                                                     Response Actions → Audit Log
```

- **`apps/backend`** — FastAPI app (`app/main.py`). Routers under
  `app/routers/` (ingest, events, entities, alerts, response, health,
  db_smoke) are thin; logic lives in `app/services/`:
  - `services/normalizer/` — `parsers/{flask,nginx}.py` parse raw log lines,
    `mapper.py` maps them into the ECS-inspired normalized schema stored
    alongside the raw payload on each event.
  - `services/detection/` — `rule_loader.py` loads/validates YAML rules
    (schema in `domain/rules/rule_schema.py`) from `RULES_DIR`; `engine.py`
    (`ThresholdEngine`) evaluates a sliding time window + count threshold per
    `group_by` field (currently single-field grouping only, e.g.
    `source.ip`), with per-rule cooldown; `runner.py` wires engine output to
    DB alert rows and is what both the worker loop and tests call
    (`run_detection_once`). Each rule evaluates independently — there is no
    cross-rule correlation (see `LEARNINGS.md` §7 for why
    `LDR-WEB-005` is a known false-positive source).
  - `services/risk/scorer.py` — computes a risk score for IP investigation
    pages.
  - `services/evidence/builder.py` — builds the evidence ZIP
    (`summary.md` + `alerts.json` + `events.json`) served from
    `GET /v1/entities/ip/{ip}/evidence`.
  - `services/response/block.py` — `BlockService`: block/unblock an IP,
    writes to `blocked_ips` and `audit_log` tables. Enforcement is
    **database-only** (no iptables/Nginx/WAF integration) — see README
    "Known limitations".
  - `services/response/audit_chain.py` — tamper-evident hash chain over
    `audit_log`: `canonical_json()` + `compute_entry_hash(prev_hash,
    **fields)` (sha256 hex) are called from `block.py:_write_audit()`
    *before* the row is inserted (the ORM's `default=` callables for
    `id`/`created_at` only populate at flush, too late for pre-insert
    hashing); `get_latest_hash()` / `verify_chain()` walk the chain in
    `created_at` order. Exposed via `GET /response/audit-log/verify` and
    `app/cli.py audit-verify`; the dashboard's "Verify integrity" button
    (`response/audit.html`, gated `role_required("admin")`) calls the same
    endpoint. Rows written before this feature shipped have `NULL`
    `prev_hash`/`entry_hash` — `verify_chain()` treats leading `NULL` rows
    as legacy and starts checking from the first hashed one. No row lock on
    "read latest hash, then insert" — a known, accepted race under
    concurrent block/unblock calls (real fix is Postgres-only
    `SELECT ... FOR UPDATE`, not testable on the SQLite unit-test path).
  - `services/notifications/email.py` — sends SMTP email for alerts whose
    severity is in `ALERT_EMAIL_SEVERITIES` (checked via
    `settings.alert_severity_set`).
  - `services/summarization/` — optional LLM alert summarization
    (`POST /v1/alerts/{id}/summary`), disabled unless `LLM_API_KEY` is set.
    `prompt_builder.py` HTML-escapes every attacker-controlled log field
    (user agent, path, referrer) into delimited `<log_field>` tags behind a
    system-prompt boundary before it reaches the model; `client.py` wraps
    the Anthropic Messages API call and never raises — disabled config,
    timeouts, and bad responses all resolve to `None` so a failed/disabled
    summarizer never breaks the alert page. Generates once per alert and
    caches the result in `alerts.summary`. Full threat model in
    `docs/ai-security-notes.md` — read it before touching this path.
  - `services/simulation/` — `SimulationRunner`, driven by `app/cli.py
    simulate`, fires synthetic attacks at a running backend and reports
    which rules fired into `docs/detection-coverage.md`. Local/demo only;
    refuses to run when `ENV=production`.
  - `services/storage/retention.py` — deletes events older than
    `EVENT_RETENTION_DAYS`, invoked via `app/cli.py retention`.
  - `app/db/models/` — SQLAlchemy 2 ORM models (`event.py`, `alert.py`,
    `blocked_ip.py`, `audit_log.py`); `app/db/migrations/` — Alembic.
    **JSONB columns must use `JSON().with_variant(JSONB(), "postgresql")`**,
    not bare `JSONB()` — unit tests run against SQLite, which cannot compile
    postgres-only DDL (see `LEARNINGS.md` §3). Same reasoning applies to the
    `.astext` accessor — use `cast(column, String)` instead for
    cross-dialect JSON field access.
  - Auth: `app/auth/agent.py` validates the `X-Agent-Token` header against
    `AGENT_TOKEN`/`AGENT_TOKEN_1` for ingest; `app/auth/dashboard.py`
    (`require_dashboard_token`) validates `X-Dashboard-Token` against
    `DASHBOARD_API_TOKEN` and is applied per-route (`Depends(...)`) on every
    handler in `routers/alerts.py`, `entities.py`, and `response.py` —
    `docker-compose.yml` publishes the backend on `8000:8000`, so without
    this, block/unblock and alert data would be directly reachable on that
    port with no auth at all, independent of dashboard login.
    `app/auth/ingest_limits.py` + `app/security/rate_limit.py` provide an
    in-memory rate limiter (reset in tests via the `reset_rate_limiter`
    fixture).
  - `app/settings.py` — Pydantic Settings loaded from `.env`; add new env
    vars here, not just in `.env.example`.

- **`apps/worker`** — `worker.py` is a bare polling loop (no framework):
  every `DETECTION_INTERVAL_SECONDS` it opens a DB session and calls
  `run_detection_once` from the backend's `app.services.detection.runner`.
  It imports the backend package directly (`PYTHONPATH` includes
  `apps/backend` in the container) rather than duplicating logic.

- **`apps/dashboard`** — Flask 3 + Jinja2 + Bootstrap 5 (dark theme).
  `dashboard/app.py` is an app factory (`create_app`) registering blueprints
  from `dashboard/routes/` (`main`, `auth`, `alerts`, `entities`, `response`).
  The dashboard is a pure API client — `dashboard/api_client.py` calls the
  FastAPI backend over HTTP (`LDR_API_BASE`, e.g. `http://backend:8000` in
  Docker), attaching `X-Dashboard-Token` (`DASHBOARD_API_TOKEN`) on every
  call to satisfy `require_dashboard_token` above, and holds no direct DB
  connection. **The dashboard must be the
  sole ingress point**: e.g. the evidence ZIP is fetched server-side by the
  dashboard and streamed to the browser, never linked directly to the
  backend, because the backend's Docker-internal hostname isn't reachable
  from a browser (see `LEARNINGS.md` §8).
  - Auth is session-based with two static roles, not a real user system:
    `dashboard/auth.py` checks credentials against `DASHBOARD_USERS`, an
    env-configured `username:werkzeug-hash:role` list (parsed in
    `dashboard/config.py`), and a global `before_request` hook
    (`login_required`) redirects any request outside `PUBLIC_ENDPOINTS` to
    `/login`. `role_required(*roles)` gates individual views — `admin` can
    block/unblock IPs via `routes/response.py`, `analyst` is
    read/investigate/triage/summarize only. CSRF protection (`Flask-WTF`
    `CSRFProtect`) covers all state-changing forms.

- **`rules/`** — YAML detection rule definitions (`LDR-WEB-001`..`006`),
  validated by `app/domain/rules/rule_schema.py` at load time. New rules
  need a schema-conformant YAML file here plus (typically) a unit test
  fixture under `apps/backend/tests/unit`.

### Cross-cutting

- Structured logging via `structlog`, configured in `app/logging.py`.
  `RequestIDMiddleware` (`app/middleware/request_id.py`) generates a
  `request_id` per request and binds it via `contextvars` so it propagates
  through logs without being threaded through function signatures.
- `app/error_handlers.py` registers global FastAPI exception handlers —
  don't catch-and-swallow errors in routers, let them surface there.
- Test paths are anchored to `__file__`, not CWD, because working directory
  differs between local runs, Docker, and CI (`LEARNINGS.md` §6) — follow
  this pattern for any new test that reads fixture files.
- Ruff (`select = ["E", "F", "I", "B"]`, line-length 100, target py312) is
  pinned identically in `pyproject.toml`, `.pre-commit-config.yaml`, and CI —
  if you bump the version, update all three (`LEARNINGS.md` §5).
- Redis is provisioned in `docker-compose.yml` but currently unused
  (reserved for a future rate-limit store / task queue); don't assume
  it's wired into any current code path.

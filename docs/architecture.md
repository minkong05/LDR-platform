# Architecture

Current state of the LDR Platform (v1.0.0 plus the portfolio-enrichment
features in `FEATURE_PLAN.md` — MITRE mapping, attack simulation, dashboard
+ API auth, LLM summarization, dashboard RBAC, and the audit hash chain are
all shipped; only VirusTotal IP-reputation enrichment is outstanding).

## Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI + Pydantic v2 + SQLAlchemy 2 |
| Dashboard | Flask 3 + Jinja2 + Bootstrap 5 |
| Database | PostgreSQL (JSONB columns) + Alembic migrations |
| Detection worker | Plain Python polling loop, YAML rules, structlog |
| Infra | Docker Compose (postgres, redis, backend, worker, dashboard) |

Redis is provisioned in `docker-compose.yml` but not wired into any code
path yet — reserved for a future rate-limit store or task queue.

## Data flow

```
Agent → Ingest API → Normaliser → Event Store (Postgres) → Detection Worker
                                                                  ↓
                                                          Alert Writer → Email
                                                                  ↓
                                                       Investigation Dashboard
                                                                  ↓
                                                     Response Actions → Audit Log
```

1. An **agent** (or `scripts/trigger_all_rules.sh` / `app.cli simulate` for
   demo data) POSTs batched raw log events to `POST /v1/ingest/events` with
   `X-Agent-Token`. Requests are deduped (stable hash) and rate-limited.
2. The **normaliser** (`services/normalizer/`) parses Flask/Nginx log
   shapes and maps them into an ECS-inspired schema, stored in Postgres
   alongside the original raw payload.
3. A **detection worker** (`apps/worker`) polls every
   `DETECTION_INTERVAL_SECONDS`, evaluates each YAML rule in `rules/`
   independently (sliding time window + count threshold per `group_by`
   field, with per-rule cooldown — there is no cross-rule correlation), and
   writes alert rows, each carrying its rule's MITRE ATT&CK technique ID.
   High/critical severity alerts trigger an SMTP notification.
4. The **investigation dashboard** (Flask) is a pure API client with no
   direct DB connection — every page is server-rendered from calls to the
   backend over `LDR_API_BASE`. Analysts browse alerts, pivot to an IP's
   timeline, view a computed risk score, deep-link an alert's MITRE
   technique to attack.mitre.org, generate an on-demand LLM summary of an
   alert, and export an evidence ZIP (streamed through the dashboard, never
   linked directly to the backend, since the backend's Docker-internal
   hostname isn't reachable from a browser).
5. **Response actions** (block/unblock an IP) are database-only — no
   iptables/Nginx/WAF integration. Every action writes a hash-chained
   `audit_log` row (sha256 over the previous entry), verifiable via
   `app.cli audit-verify` or the dashboard's "Verify integrity" button.

## Auth model (two independent layers)

- **Ingest**: `X-Agent-Token` (`AGENT_TOKEN`/`AGENT_TOKEN_1`), checked in
  `app/auth/agent.py`. Protects `POST /v1/ingest/events` only.
- **Backend API**: `X-Dashboard-Token` (`DASHBOARD_API_TOKEN`), checked in
  `app/auth/dashboard.py` and applied per-route on every handler in
  `routers/alerts.py`, `entities.py`, `response.py`. This exists because
  `docker-compose.yml` publishes the backend on `8000:8000` — without it,
  block/unblock and alert data would be directly reachable on that port
  with no auth at all, regardless of dashboard login.
- **Dashboard UI**: session-based login (`dashboard/auth.py`) against
  `DASHBOARD_USERS`, an env-configured `username:werkzeug-hash:role` list —
  not a database `users` table. Two roles: `admin` (full access, including
  block/unblock and audit-chain verify) and `analyst` (read/investigate/
  triage/summarize only). CSRF protection (Flask-WTF) covers all
  state-changing forms.

These three tokens/credentials are independent — rotating one does not
affect the others.

## Optional / disabled-by-default integrations

Both follow the same resilience contract: disabled via an empty API key,
never raise (structlog on failure instead), and the relevant UI card is
simply absent rather than erroring.

- **LLM alert summarization** (`services/summarization/`) — `LLM_API_KEY`
  unset (default, and CI's setting) disables it entirely; no network call
  is attempted. See `docs/ai-security-notes.md` for the prompt-injection
  threat model (attacker-controlled fields like `user_agent`/`url.path`
  flow into the prompt) and mitigations.
- **VirusTotal IP reputation** — planned (`FEATURE_PLAN.md` Feature 3b),
  not yet implemented.

## Guardrails

- Agent token auth + dashboard token auth (above) + in-memory ingest rate
  limiting (`app/security/rate_limit.py`).
- Structured JSON logging (`structlog`) with a per-request `request_id`
  propagated via `contextvars` (`app/middleware/request_id.py`).
- Global FastAPI exception handlers (`app/error_handlers.py`) — routers
  don't catch-and-swallow errors.
- `app.cli simulate` (attack simulation) refuses to run when
  `ENV=production` and always targets `localhost:8000` by default, never
  `LDR_API_BASE`, so it can't accidentally fire synthetic attacks at a real
  deployment.

See `README.md` "Known limitations" for the full list of intentional scope
boundaries (no cross-rule correlation, DB-only block enforcement, single
SMTP recipient, no OAuth/SSO, audit chain has no backfill, etc.) and
`LEARNINGS.md` for the design rationale and failure modes behind these
decisions.

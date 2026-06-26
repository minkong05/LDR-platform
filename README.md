<!-- 📄 README.md -->

![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)
![CI](https://github.com/minkong05/LDR-platform/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)

# Lightweight Detection & Response (LDR) Platform

A self-built mini SOC platform for web services — built over 16 weeks as a
learning and portfolio project. Ingests logs from Flask and Nginx, normalises
them into an ECS-inspired schema, runs YAML-based detection rules, surfaces
alerts in an investigation dashboard, and supports safe response actions with
a full audit trail.

> **Status: v1.0.0 complete.** All four months of the roadmap are done.


## What it does

```
Agent → Ingest API → Normaliser → Event Store → Detection Worker
                                                       ↓
                                                Alert Writer → Email
                                                       ↓
                                              Investigation Dashboard
                                                       ↓
                                            Response Actions → Audit Log
```

1. A log **agent** ships batched events (Flask access logs, Nginx access logs)
   to the ingest API with a shared secret token.
2. The **ingest API** dedupes, rate-limits, parses, and normalises each event
   into an ECS-inspired schema, then stores it in PostgreSQL.
3. A **detection worker** polls every 30 seconds, evaluates YAML threshold
   rules against recent events, and writes alerts to the database. High and
   critical alerts trigger email notifications.
4. The **investigation dashboard** (Flask + Bootstrap 5) lets an analyst
   browse alerts, pivot to IP timelines, review risk scores, and export
   evidence bundles as ZIP files.
5. From any IP investigation page, the analyst can **block or unblock** the IP
   with one click. Every action is written to an immutable **audit log**
   visible in the dashboard.


## Roadmap

- [x] Ingestion API — agent token auth, stable dedupe hash, rate limiting
- [x] Normalisation — Nginx + Flask parsers → ECS-inspired schema
- [x] Event store + query endpoints — filter, paginate, IP summary
- [x] Operational basics — structured logs, request-id, global error handling, retention CLI
- [x] Detection engine — YAML rule loader, threshold windows, alert writer
- [x] Email notifications — high/critical alerts trigger SMTP email
- [x] Investigation dashboard — alert list, alert detail, triage workflow
- [x] IP investigation — event timeline, risk scoring, top paths, status codes
- [x] Evidence export — ZIP bundle (summary.md + alerts.json + events.json)
- [x] Response actions — block IP, unblock IP, block status — full audit trail
- [x] Audit log dashboard — paginated view of all response actions


## Tech stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI + Pydantic v2 + SQLAlchemy 2 |
| Dashboard | Flask 3 + Bootstrap 5 dark theme + Jinja2 |
| Database | PostgreSQL (JSONB columns) + Alembic migrations |
| Detection worker | Python polling loop, YAML rules, structlog |
| Auth | Shared agent token (X-Agent-Token header) |
| Testing | pytest — unit + integration (RUN_INTEGRATION_TESTS=1) |
| CI | GitHub Actions |
| Infrastructure | Docker Compose |


## Quickstart

```bash
git clone https://github.com/minkong05/LDR-platform.git
cd LDR-platform
cp .env.example .env        # review defaults before running
./scripts/dev_up.sh         # starts postgres, backend, worker, dashboard

# Verify stack is up
curl http://localhost:8000/v1/health   # {"status": "ok"}
open http://localhost:5001             # dashboard
```

### Seed demo data

```bash
# Trigger all detection rules with synthetic events
./scripts/trigger_all_rules.sh

# Wait ~30 seconds for the worker to fire, then open the dashboard
open http://localhost:5001
```


## Project structure

```
LDR-platform/
├── apps/
│   ├── backend/          # FastAPI — ingest, events, alerts, entities, response
│   │   ├── app/
│   │   │   ├── routers/
│   │   │   ├── services/ # detection, normaliser, risk, evidence, email, response
│   │   │   ├── db/       # ORM models + Alembic migrations
│   │   │   └── schemas/
│   │   └── tests/        # unit + integration
│   ├── worker/           # detection polling loop
│   └── dashboard/        # Flask UI
│       └── dashboard/
│           ├── routes/
│           └── templates/
├── rules/                # YAML detection rules
├── scripts/              # dev helpers
└── docs/
```


## Detection rules

Rules live in `rules/` as YAML files. Example:

```yaml
id: LDR-WEB-001
name: Brute force login failures
severity: high
confidence: high
technique_id: T1110
condition:
  type: threshold
  field: event.action
  value: login_failed
  threshold: 10
  window_seconds: 300
  group_by:
    - source.ip
```

The engine evaluates each rule against a sliding window of normalised events.
When the threshold is crossed, an alert is written with a computed risk score.


## Tests

```bash
# Unit tests (no external dependencies)
pytest -q

# Integration tests (requires running Postgres)
docker compose up -d postgres
RUN_INTEGRATION_TESTS=1 pytest -q

# Run everything
./scripts/test_all.sh
```

## Known limitations

These are intentional design decisions and environment constraints, not bugs.

- **Block enforcement is database-only.** Blocking an IP writes a record to
  PostgreSQL and the audit log. There is no Nginx or firewall enforcement —
  the platform is designed for a constrained local environment where system
  network config is not accessible. The architecture is designed so a real
  enforcement layer (iptables, Nginx `geo` block, cloud WAF) could read the
  `blocked_ips` table to enforce.
- **Single SMTP recipient.** Email notifications go to one address
  (`SMTP_TO`). Multi-recipient or on-call routing is not implemented.
- **No authentication on the dashboard.** The Flask dashboard has no login
  wall. Intended for internal/local use only.
- **No cross-rule correlation.** The detection engine evaluates each rule
  independently. There is no support for "fire when rule A AND rule B both
  trigger for the same IP".
- **Redis is provisioned but unused.** The Docker Compose stack includes
  Redis, reserved for a future rate-limit store or task queue. The current
  in-memory rate limiter is used instead.


## Author

Built by **Kong Yu Min**  
University of Glasgow  
Python | Backend | Security

[GitHub](https://github.com/minkong05) · [LinkedIn](https://linkedin.com/in/your-handle)


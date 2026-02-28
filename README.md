![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)
![Postgres](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)
![CI](https://github.com/minkong05/Flask-Learnpython/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)

# Lightweight Detection & Response Platform (LDR) for Web Services
A mini SOC-style platform for small web services: ingest logs (Nginx + Flask + Docker), normalize into an ECS-inspired schema, run explainable detections, investigate entities (IP timelines/stats), and support safe response actions with full auditing.

## Project status
**Status:** In progress (Foundation/MVP complete)
**Current focus (Week 1–4):** ingestion → normalization → storage → query APIs  
**Next (Weeks 5–8):** detection rules + alert generation + alert APIs  
**Later (Weeks 9–16):** investigation UI, evidence export, response actions + auditing

## Roadmap
- [x] Ingestion API (auth, dedupe, rate limiting)
- [x] Normalization (nginx + flask) → ECS-inspired schema
- [x] Event store + query endpoints (+ IP summary)
- [x] Operational basics (structured logs, request-id, error handling, retention CLI)
- [ ] Detection MVP (rule loader, thresholds, alert table)
- [ ] Investigation UX (timeline, pivots, evidence export)
- [ ] Response actions (block IP / revoke sessions) + full audit trail



## What’s implemented (current)
- FastAPI backend with Docker Compose stack (Postgres + Redis + backend)
- Ingestion API: `POST /v1/ingest/events`
  - Agent token auth
  - Stable dedupe hash
  - Rate limiting (guardrail)
- Normalization:
  - Nginx access line parsing → HTTP method/path/status/bytes/UA mapped into normalized schema
  - Flask JSON parsing → action/outcome/user/route_group mapped into normalized schema
- Storage:
  - Postgres `events` table (migrations via Alembic)
- Query / investigation APIs:
  - `GET /v1/events` (filter + pagination)
  - `GET /v1/entities/ip/{ip}` (summary stats: counts, top paths, status codes)
- Operational:
  - Structured JSON logs + request-id
  - Global error handling
  - Retention cleanup CLI (manual) + helper script


## Quickstart (local)
```bash
cp .env.example .env
./scripts/dev_up.sh
curl http://localhost:8000/v1/health
```

## Demo (Week 1)
See the step-by-step demo script: [demo-script.md](docs/demo/demo-script.md)


## Tests
- Unit tests: `pytest -q`
- Integration tests (requires Postgres): 
  - `docker compose up -d postgres`
  - `RUN_INTEGRATION_TESTS=1 pytest -q`
- Run all (recommended): `./scripts/test_all.sh`


## Retention cleanup
- `./scripts/retention.sh 14`


## Security guardrails (baseline)
- Defensive-only design
- Ingestion auth via agent token
- Input validation via Pydantic
- Rate limiting on ingestion
- Request IDs + structured logs


## Roadmap (high level)
- Month 2: detection engine (YAML rules + threshold windows) + alerts API
- Month 3: investigation UX + evidence export bundle
- Month 4: safe response actions + audit trail + RBAC + demo polish



## Author
Built by **Kong Yu Min**  
University of Glasgow  
Python | Backend | Security

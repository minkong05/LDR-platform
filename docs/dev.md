# Development Guide

## Run locally
- `cp .env.example .env`
- `docker compose up -d --build`
- Health: `curl http://localhost:8000/v1/health`

## Tests
- Unit only: `pytest -q`
- Integration (Postgres): `RUN_INTEGRATION_TESTS=1 pytest -q`

## Retention cleanup
Deletes events older than N days (based on `event_timestamp`).

Run:
- `PYTHONPATH=apps/backend python -m app.cli retention --days 14`

Default days:
- `EVENT_RETENTION_DAYS` in `.env` (defaults to 14)

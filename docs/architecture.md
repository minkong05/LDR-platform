# Architecture (current)

## Stack
- FastAPI backend (Dockerized)
- Postgres (events store)
- Redis (reserved for worker / future rate limit store)
- Worker container (placeholder for Month 2 detection engine)

## Data flow (today)
1) Agent sends batched events to `POST /v1/ingest/events` with `X-Agent-Token`
2) Backend dedupes and stores:
   - `raw` (original payload + parsed helpers)
   - `normalized` (ECS-inspired minimal schema)
3) Investigation APIs:
   - `GET /v1/events`
   - `GET /v1/entities/ip/{ip}`

## Guardrails
- Agent auth
- Rate limiting
- Structured logs + request ID
- Global exception handling

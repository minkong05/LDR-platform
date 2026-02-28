# LDR Demo Script (Week 1)

## 0) Start stack
- `cp .env.example .env`
- `./scripts/dev_up.sh`

## 1) Ingest a realistic nginx login failure
```bash
curl -X POST http://localhost:8000/v1/ingest/events \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $(grep '^AGENT_TOKEN=' .env | cut -d= -f2-)" \
  -d '{"events":[{"event_timestamp":"2026-02-21T20:00:00Z","log_source":"nginx","service_name":"demo-web","source_ip":"0.0.0.0","raw":{"nginx_line":"203.0.113.55 - - [2026-02-21T20:00:00+00:00] \"POST /login HTTP/1.1\" 401 530 \"-\" \"Mozilla/5.0\""}}]}'
```

## 2) Show the event landed and normalized
- `curl "http://localhost:8000/v1/events?limit=1" | jq .`


## 3) Show investigation-style IP summary
- `curl "http://localhost:8000/v1/entities/ip/203.0.113.55" | jq .`

## 4) Show ingestion guardrail (rate limiting)
Run ~80 quick requests and observe 429s after the limit:
```bash
TOKEN="$(grep '^AGENT_TOKEN=' .env | cut -d= -f2-)"
URL="http://localhost:8000/v1/ingest/events"

for i in $(seq 1 80); do
  code=$(
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$URL" \
      -H "Content-Type: application/json" \
      -H "X-Agent-Token: $TOKEN" \
      -d '{"events":[{"event_timestamp":"2026-02-21T20:00:00Z","log_source":"flask","service_name":"demo-web","source_ip":"203.0.113.55","raw":{"msg":"hi"}}]}'
  )
  echo "$i -> $code"
done
```
# LDR Demo Script

End-to-end walkthrough of the platform as it stands today (ingestion →
detection → dashboard investigation → response → audit). Credentials below
match the `admin`/`analyst` entries checked into `.env.example`
(`test123` for both) — change them before using this anywhere but a local
demo.

## 0) Start the stack

```bash
cp .env.example .env
./scripts/dev_up.sh
curl http://localhost:8000/v1/health   # {"status": "ok"}
```

## 1) Ingest a raw event and see it normalised

```bash
curl -X POST http://localhost:8000/v1/ingest/events \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: $(grep '^AGENT_TOKEN=' .env | cut -d= -f2-)" \
  -d '{"events":[{"event_timestamp":"2026-07-27T20:00:00Z","log_source":"nginx","service_name":"demo-web","source_ip":"0.0.0.0","raw":{"nginx_line":"203.0.113.55 - - [2026-07-27T20:00:00+00:00] \"POST /login HTTP/1.1\" 401 530 \"-\" \"Mozilla/5.0\""}}]}'
```

The backend API itself requires a *second* token
(`X-Dashboard-Token: $DASHBOARD_API_TOKEN`) on `/v1/events`, `/v1/alerts`,
`/v1/entities/*`, and `/v1/response/*` — this is what the dashboard sends
on your behalf; direct `curl` calls to those routes need the header too.

```bash
curl -H "X-Dashboard-Token: $(grep '^DASHBOARD_API_TOKEN=' .env | cut -d= -f2-)" \
  "http://localhost:8000/v1/events?limit=1" | jq .

curl -H "X-Dashboard-Token: $(grep '^DASHBOARD_API_TOKEN=' .env | cut -d= -f2-)" \
  "http://localhost:8000/v1/entities/ip/203.0.113.55" | jq .
```

## 2) Trigger every detection rule

Either the fast bash version:

```bash
./scripts/trigger_all_rules.sh
```

or the testable Python tool, which also reports coverage gaps against
common web-attack ATT&CK techniques:

```bash
PYTHONPATH=apps/backend python -m app.cli simulate
cat docs/detection-coverage.md
```

Wait ~30–35 seconds for the worker to evaluate (`DETECTION_INTERVAL_SECONDS`).

## 3) Dashboard walkthrough

```bash
open http://localhost:5001
```

- Log in as `admin` / `test123`.
- **Alerts** (`/alerts/`) — list of fired alerts by severity/rule.
- Open an alert (`/alerts/<id>`):
  - MITRE ATT&CK technique badge links out to `attack.mitre.org`
    (sub-techniques like `T1110.004` resolve to the correct `/T1110/004/`
    URL, not a 404).
  - Click **Generate Summary** to trigger the on-demand LLM summarizer
    (`POST /alerts/<id>/summary`) — requires `LLM_API_KEY` set, otherwise
    the card is simply absent and nothing else on the page changes. See
    `docs/ai-security-notes.md` for the prompt-injection threat model this
    defends against.
  - Triage the alert (acknowledge/resolve).
- Pivot to the source IP (`/entities/ip/<ip>`):
  - Event timeline, computed risk score, top paths/status codes.
  - Export the evidence ZIP (`summary.md` + `alerts.json` + `events.json`)
    — streamed through the dashboard, never linked directly to the backend.
  - Block/unblock the IP (admin-only forms; an `analyst` session sees a
    read-only view with no block/unblock controls at all).

## 4) Response actions + tamper-evident audit trail

After blocking/unblocking a couple of IPs from the dashboard:

- **Audit log** (`/response/audit`) — every action, paginated.
- Click **Verify integrity** (admin-only) to recompute the sha256 hash
  chain over `audit_log` and confirm no row has been tampered with — or
  run the same check from the CLI:

```bash
PYTHONPATH=apps/backend python -m app.cli audit-verify
```

To see it *fail* on purpose, tamper with a row directly and re-run:

```bash
docker compose exec postgres psql -U ldr -d ldr \
  -c "UPDATE audit_log SET detail = detail || '{\"tampered\": true}' WHERE id = (SELECT MIN(id) FROM audit_log WHERE entry_hash IS NOT NULL);"
PYTHONPATH=apps/backend python -m app.cli audit-verify   # now reports the tampered row
```

## 5) Role-based access control

Log out, log back in as `analyst` / `test123`:

- Alerts, IP investigation, evidence export, and summary generation all
  still work.
- Block/unblock forms are hidden entirely on the IP page (not just
  rejected on submit).
- `GET /response/audit/verify` (and its "Verify integrity" button) returns
  403 for this role.

## 6) Ingestion guardrail: rate limiting

```bash
TOKEN="$(grep '^AGENT_TOKEN=' .env | cut -d= -f2-)"
URL="http://localhost:8000/v1/ingest/events"

for i in $(seq 1 80); do
  code=$(
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$URL" \
      -H "Content-Type: application/json" \
      -H "X-Agent-Token: $TOKEN" \
      -d '{"events":[{"event_timestamp":"2026-07-27T20:00:00Z","log_source":"flask","service_name":"demo-web","source_ip":"203.0.113.55","raw":{"msg":"hi"}}]}'
  )
  echo "$i -> $code"
done
```

Expect `200`s followed by `429`s once `INGEST_RATE_LIMIT` is exceeded.

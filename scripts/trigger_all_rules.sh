#!/usr/bin/env bash
# 📄 scripts/trigger_all_rules.sh
# Triggers all LDR detection rules by sending batched events to the ingest API.
# Usage: ./scripts/trigger_all_rules.sh

set -euo pipefail

TOKEN="dev-agent-token-change-me"
BASE_URL="http://localhost:8000"
INGEST="${BASE_URL}/v1/ingest/events"

IP_001="203.0.113.10"
IP_002="203.0.113.20"
IP_003="203.0.113.30"
IP_004="203.0.113.40"
IP_005="203.0.113.50"
IP_006="203.0.113.60"

echo "========================================"
echo " LDR — trigger all rules (batched)"
echo "========================================"

# Helper: build a flask event JSON object with a unique timestamp offset
flask_event() {
  local ip=$1 path=$2 status=$3 action=$4 route=$5 user=$6 offset=$7
  local ts
  ts=$(date -u -v+"${offset}"S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -d "+${offset} seconds" +%Y-%m-%dT%H:%M:%SZ)
  printf '{
    "event_timestamp": "%s",
    "log_source": "flask",
    "service_name": "demo-web",
    "source_ip": "%s",
    "raw": {"ip":"%s","method":"POST","path":"%s","status":%s,"action":"%s","route_group":"%s","username":"%s"}
  }' "$ts" "$ip" "$ip" "$path" "$status" "$action" "$route" "$user"
}

nginx_event() {
  local ip=$1 path=$2 status=$3 ua=$4 offset=$5
  local ts tslog
  ts=$(date -u -v+"${offset}"S +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -d "+${offset} seconds" +%Y-%m-%dT%H:%M:%SZ)
  tslog=$(date -u -v+"${offset}"S '+%Y-%m-%dT%H:%M:%S+00:00' 2>/dev/null \
    || date -u -d "+${offset} seconds" '+%Y-%m-%dT%H:%M:%S+00:00')
  printf '{
    "event_timestamp": "%s",
    "log_source": "nginx",
    "service_name": "demo-web",
    "source_ip": "%s",
    "raw": {"nginx_line": "%s - - [%s] \\"GET %s HTTP/1.1\\" %s 0 \\"-\\" \\"%s\\""}
  }' "$ts" "$ip" "$ip" "$tslog" "$path" "$status" "$ua"
}

# ── LDR-WEB-001: 12 flask login_failed ───────────────────────────────────────
echo ""
echo "→ LDR-WEB-001: 12 login_failed (flask) from ${IP_001}"
events=""
for i in $(seq 1 12); do
  ev=$(flask_event "$IP_001" "/login" 401 "login_failed" "auth" "user${i}" "$i")
  events="${events}${events:+,}${ev}"
done
curl -s -X POST "$INGEST" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ${TOKEN}" \
  -d "{\"events\": [${events}]}" | jq '{inserted, deduped}'

# ── LDR-WEB-002: 22 nginx 401s ───────────────────────────────────────────────
echo ""
echo "→ LDR-WEB-002: 22 nginx 401s from ${IP_002}"
events=""
for i in $(seq 1 22); do
  ev=$(nginx_event "$IP_002" "/login" 401 "python-requests/2.31" "$i")
  events="${events}${events:+,}${ev}"
done
curl -s -X POST "$INGEST" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ${TOKEN}" \
  -d "{\"events\": [${events}]}" | jq '{inserted, deduped}'

# ── LDR-WEB-003: 6 nginx 403s on /admin ─────────────────────────────────────
echo ""
echo "→ LDR-WEB-003: 6 nginx 403s on /admin from ${IP_003}"
events=""
for i in $(seq 1 6); do
  ev=$(nginx_event "$IP_003" "/admin" 403 "curl/7.88" "$i")
  events="${events}${events:+,}${ev}"
done
curl -s -X POST "$INGEST" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ${TOKEN}" \
  -d "{\"events\": [${events}]}" | jq '{inserted, deduped}'

# ── LDR-WEB-004: 32 nginx 404s ───────────────────────────────────────────────
echo ""
echo "→ LDR-WEB-004: 32 nginx 404s from ${IP_004}"
events=""
for i in $(seq 1 32); do
  ev=$(nginx_event "$IP_004" "/probe/path${i}" 404 "gobuster/3.6" "$i")
  events="${events}${events:+,}${ev}"
done
curl -s -X POST "$INGEST" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ${TOKEN}" \
  -d "{\"events\": [${events}]}" | jq '{inserted, deduped}'

# ── LDR-WEB-005: 1 flask login_success ───────────────────────────────────────
echo ""
echo "→ LDR-WEB-005: 1 login_success (flask) from ${IP_005}"
ev=$(flask_event "$IP_005" "/login" 200 "login_success" "auth" "victim_user" "0")
curl -s -X POST "$INGEST" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ${TOKEN}" \
  -d "{\"events\": [${ev}]}" | jq '{inserted, deduped}'

# ── LDR-WEB-006: 16 flask login_failed ───────────────────────────────────────
echo ""
echo "→ LDR-WEB-006: 16 login_failed (flask) from ${IP_006}"
events=""
for i in $(seq 1 16); do
  ev=$(flask_event "$IP_006" "/login" 401 "login_failed" "auth" "enum_user${i}" "$i")
  events="${events}${events:+,}${ev}"
done
curl -s -X POST "$INGEST" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ${TOKEN}" \
  -d "{\"events\": [${events}]}" | jq '{inserted, deduped}'

echo ""
echo "========================================"
echo " All events sent (6 requests total)."
echo " Worker fires every 30s — wait up to 30s"
echo " then check: http://localhost:5001/alerts"
echo "========================================"
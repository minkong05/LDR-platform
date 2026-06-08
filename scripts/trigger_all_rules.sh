#!/usr/bin/env bash
# 📄 scripts/trigger_all_rules.sh
# Triggers all LDR detection rules by sending matching events to the ingest API.
# Usage: ./scripts/trigger_all_rules.sh

set -euo pipefail

TOKEN="dev-agent-token-change-me"
BASE_URL="http://localhost:8000"
INGEST="${BASE_URL}/v1/ingest/events"

# Each rule uses a different IP so alerts are isolated and don't interfere
IP_001="203.0.113.10"   # LDR-WEB-001 brute force
IP_002="203.0.113.20"   # LDR-WEB-002 credential stuffing
IP_003="203.0.113.30"   # LDR-WEB-003 admin probing
IP_004="203.0.113.40"   # LDR-WEB-004 404 scanning
IP_005="203.0.113.50"   # LDR-WEB-005 login success after failures
IP_006="203.0.113.60"   # LDR-WEB-006 account enumeration

echo "========================================"
echo " LDR — trigger all rules"
echo "========================================"

# ── LDR-WEB-001: Brute force login failures ───────────────────────────────────
# match: event.action=login_failed, labels.route_group=auth, url.path=/login
# condition: 10 events in 5m
echo ""
echo "→ LDR-WEB-001: sending 12 login_failed (flask) from ${IP_001}"
for i in $(seq -w 1 12); do
  curl -s -X POST "${INGEST}" \
    -H "Content-Type: application/json" \
    -H "X-Agent-Token: ${TOKEN}" \
    -d "{
      \"events\": [{
        \"event_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"log_source\": \"flask\",
        \"service_name\": \"demo-web\",
        \"source_ip\": \"${IP_001}\",
        \"raw\": {
          \"ip\": \"${IP_001}\",
          \"method\": \"POST\",
          \"path\": \"/login\",
          \"status\": 401,
          \"action\": \"login_failed\",
          \"route_group\": \"auth\",
          \"username\": \"user${i}\"
        }
      }]
    }" > /dev/null
  echo "   event ${i}"
  sleep 0.1
done

# ── LDR-WEB-002: Credential stuffing — high 401 rate ─────────────────────────
# match: http.response.status_code=401
# condition: 20 events in 2m
echo ""
echo "→ LDR-WEB-002: sending 22 nginx 401s from ${IP_002}"
for i in $(seq -w 1 22); do
  curl -s -X POST "${INGEST}" \
    -H "Content-Type: application/json" \
    -H "X-Agent-Token: ${TOKEN}" \
    -d "{
      \"events\": [{
        \"event_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"log_source\": \"nginx\",
        \"service_name\": \"demo-web\",
        \"source_ip\": \"${IP_002}\",
        \"raw\": {
          \"nginx_line\": \"${IP_002} - - [$(date -u '+%Y-%m-%dT%H:%M:%S+00:00')] \\\"POST /login HTTP/1.1\\\" 401 120 \\\"-\\\" \\\"python-requests/2.31\\\"\"
        }
      }]
    }" > /dev/null
  echo "   event ${i}"
  sleep 0.1
done

# ── LDR-WEB-003: Admin panel probing ─────────────────────────────────────────
# match: url.path=/admin, http.response.status_code=403
# condition: 5 events in 10m
echo ""
echo "→ LDR-WEB-003: sending 6 nginx 403s on /admin from ${IP_003}"
for i in $(seq -w 1 6); do
  curl -s -X POST "${INGEST}" \
    -H "Content-Type: application/json" \
    -H "X-Agent-Token: ${TOKEN}" \
    -d "{
      \"events\": [{
        \"event_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"log_source\": \"nginx\",
        \"service_name\": \"demo-web\",
        \"source_ip\": \"${IP_003}\",
        \"raw\": {
          \"nginx_line\": \"${IP_003} - - [$(date -u '+%Y-%m-%dT%H:%M:%S+00:00')] \\\"GET /admin HTTP/1.1\\\" 403 89 \\\"-\\\" \\\"curl/7.88\\\"\"
        }
      }]
    }" > /dev/null
  echo "   event ${i}"
  sleep 0.1
done

# ── LDR-WEB-004: 404 path scanning ───────────────────────────────────────────
# match: http.response.status_code=404
# condition: 30 events in 3m
echo ""
echo "→ LDR-WEB-004: sending 32 nginx 404s from ${IP_004}"
for i in $(seq -w 1 32); do
  curl -s -X POST "${INGEST}" \
    -H "Content-Type: application/json" \
    -H "X-Agent-Token: ${TOKEN}" \
    -d "{
      \"events\": [{
        \"event_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"log_source\": \"nginx\",
        \"service_name\": \"demo-web\",
        \"source_ip\": \"${IP_004}\",
        \"raw\": {
          \"nginx_line\": \"${IP_004} - - [$(date -u '+%Y-%m-%dT%H:%M:%S+00:00')] \\\"GET /probe/path${i} HTTP/1.1\\\" 404 0 \\\"-\\\" \\\"gobuster/3.6\\\"\"
        }
      }]
    }" > /dev/null
  echo "   event ${i}"
  sleep 0.05
done

# ── LDR-WEB-005: Login success after brute force ──────────────────────────────
# match: event.action=login_success, labels.route_group=auth
# condition: 1 event in 1m
echo ""
echo "→ LDR-WEB-005: sending 1 login_success (flask) from ${IP_005}"
curl -s -X POST "${INGEST}" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Token: ${TOKEN}" \
  -d "{
    \"events\": [{
      \"event_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"log_source\": \"flask\",
      \"service_name\": \"demo-web\",
      \"source_ip\": \"${IP_005}\",
      \"raw\": {
        \"ip\": \"${IP_005}\",
        \"method\": \"POST\",
        \"path\": \"/login\",
        \"status\": 200,
        \"action\": \"login_success\",
        \"route_group\": \"auth\",
        \"username\": \"victim_user\"
      }
    }]
  }" > /dev/null
echo "   event 1"

# ── LDR-WEB-006: Account enumeration ─────────────────────────────────────────
# match: event.action=login_failed, event.outcome=failure
# condition: 15 events in 5m
echo ""
echo "→ LDR-WEB-006: sending 16 login_failed (flask) from ${IP_006}"
for i in $(seq -w 1 16); do
  curl -s -X POST "${INGEST}" \
    -H "Content-Type: application/json" \
    -H "X-Agent-Token: ${TOKEN}" \
    -d "{
      \"events\": [{
        \"event_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"log_source\": \"flask\",
        \"service_name\": \"demo-web\",
        \"source_ip\": \"${IP_006}\",
        \"raw\": {
          \"ip\": \"${IP_006}\",
          \"method\": \"POST\",
          \"path\": \"/login\",
          \"status\": 401,
          \"action\": \"login_failed\",
          \"route_group\": \"auth\",
          \"username\": \"enum_user${i}\"
        }
      }]
    }" > /dev/null
  echo "   event ${i}"
  sleep 0.1
done

echo ""
echo "========================================"
echo " All events sent."
echo " Worker fires every 30s — wait up to 30s"
echo " then check: http://localhost:5001/alerts"
echo "========================================"
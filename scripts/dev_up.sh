#!/usr/bin/env bash
set -euo pipefail

docker compose up -d --build
echo "Backend: http://localhost:8000"
echo "Health:  curl http://localhost:8000/v1/health"

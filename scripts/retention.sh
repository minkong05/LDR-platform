#!/usr/bin/env bash
set -euo pipefail

DAYS="${1:-14}"

# Ensure we use the repo venv if present
if [ -f ".venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
PYTHONPATH=apps/backend python -m app.cli retention --days "$DAYS"

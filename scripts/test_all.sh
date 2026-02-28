#!/usr/bin/env bash
set -euo pipefail

# Unit tests
pytest -q

# Integration tests
docker compose up -d postgres
RUN_INTEGRATION_TESTS=1 pytest -q

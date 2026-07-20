# 📄 apps/dashboard/dashboard/api_client.py

from __future__ import annotations

import requests
from flask import current_app


def _base() -> str:
    return current_app.config["LDR_API_BASE"].rstrip("/")


def _timeout() -> int:
    return current_app.config["API_TIMEOUT"]


def _headers() -> dict:
    return {"X-Dashboard-Token": current_app.config["DASHBOARD_API_TOKEN"]}


def get(path: str, params: dict | None = None) -> dict:
    """GET /v1/... and return parsed JSON. Raises on HTTP errors."""
    url = f"{_base()}{path}"
    resp = requests.get(url, params=params, headers=_headers(), timeout=_timeout())
    resp.raise_for_status()
    return resp.json()


def post(path: str, payload: dict | None = None) -> dict:
    """POST /v1/... with JSON body and return parsed JSON. Raises on HTTP errors."""
    url = f"{_base()}{path}"
    resp = requests.post(url, json=payload or {}, headers=_headers(), timeout=_timeout())
    resp.raise_for_status()
    return resp.json()


def patch(path: str, payload: dict) -> dict:
    """PATCH /v1/... with JSON body and return parsed JSON."""
    url = f"{_base()}{path}"
    resp = requests.patch(url, json=payload, headers=_headers(), timeout=_timeout())
    resp.raise_for_status()
    return resp.json()

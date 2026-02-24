from datetime import datetime
from typing import Any


def normalize_event(
    *,
    event_timestamp: datetime,
    log_source: str,
    service_name: str,
    source_ip: str,
    raw: dict[str, Any],
    parsed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    v1 normalizer:
    - Minimal ECS-inspired fields
    - Optional parsed fields for nginx/flask/docker
    """
    parsed = parsed or {}

    # Prefer parsed source_ip if available
    ip = parsed.get("source_ip") or source_ip

    normalized: dict[str, Any] = {
        "@timestamp": event_timestamp.isoformat(),
        "event": {
            "kind": "event",
            "category": ["web"] if log_source in {"nginx", "flask"} else ["host"],
            "type": ["access"] if log_source in {"nginx", "flask"} else ["info"],
            "action": raw.get("action") or "log_ingested",
            "outcome": raw.get("outcome") or "unknown",
        },
        "log": {"source": log_source},
        "service": {"name": service_name},
        "source": {"ip": ip},
        "labels": {"env": raw.get("env", "local")},
    }

    # Map nginx HTTP fields if present
    if parsed.get("http_method") and parsed.get("url_path"):
        normalized["http"] = {
            "request": {"method": parsed["http_method"]},
            "response": {"status_code": parsed.get("status_code")},
        }
        normalized["url"] = {"path": parsed["url_path"]}

    if parsed.get("user_agent"):
        normalized["user_agent"] = {"original": parsed["user_agent"]}

    if parsed.get("response_bytes") is not None:
        normalized.setdefault("http", {}).setdefault("response", {})["bytes"] = parsed[
            "response_bytes"
        ]

    return normalized

from datetime import datetime
from typing import Any


def _derive_outcome_from_status(status_code: int | None) -> str:
    if status_code is None:
        return "unknown"
    return "failure" if status_code >= 400 else "success"


def normalize_event(
    *,
    event_timestamp: datetime,
    log_source: str,
    service_name: str,
    source_ip: str,
    raw: dict[str, Any],
    parsed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    parsed = parsed or {}

    ip = parsed.get("source_ip") or source_ip

    status_code = parsed.get("status_code")
    action = parsed.get("action") or raw.get("action") or "log_ingested"
    outcome = (
        raw.get("outcome") or parsed.get("outcome") or _derive_outcome_from_status(status_code)
    )

    normalized: dict[str, Any] = {
        "@timestamp": event_timestamp.isoformat(),
        "event": {
            "kind": "event",
            "category": ["web"] if log_source in {"nginx", "flask"} else ["host"],
            "type": ["access"] if log_source in {"nginx", "flask"} else ["info"],
            "action": action,
            "outcome": outcome,
        },
        "log": {"source": log_source},
        "service": {"name": service_name},
        "source": {"ip": ip},
        "labels": {"env": raw.get("env", "local")},
    }

    # Route group tagging (auth/api/admin)
    if parsed.get("route_group"):
        normalized["labels"]["route_group"] = parsed["route_group"]

    # Username if present (attempted or authenticated)
    if parsed.get("username"):
        normalized["user"] = {"name": parsed["username"]}

    # HTTP mapping
    if parsed.get("http_method") and parsed.get("url_path"):
        normalized["http"] = {
            "request": {"method": parsed["http_method"]},
            "response": {"status_code": status_code},
        }
        normalized["url"] = {"path": parsed["url_path"]}

    if parsed.get("user_agent"):
        normalized["user_agent"] = {"original": parsed["user_agent"]}

    if parsed.get("response_bytes") is not None:
        normalized.setdefault("http", {}).setdefault("response", {})["bytes"] = parsed[
            "response_bytes"
        ]

    return normalized

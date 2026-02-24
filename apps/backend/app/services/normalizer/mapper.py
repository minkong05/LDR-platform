from datetime import datetime
from typing import Any


def normalize_event(
    *,
    event_timestamp: datetime,
    log_source: str,
    service_name: str,
    source_ip: str,
    raw: dict[str, Any],
) -> dict[str, Any]:
    """
    v0 normalizer:
    - Produces a consistent, minimal ECS-inspired structure
    - Leaves deeper parsing/enrichment for later steps
    """
    return {
        "@timestamp": event_timestamp.isoformat(),
        "event": {
            "kind": "event",
            "category": ["web"] if log_source in {"nginx", "flask"} else ["host"],
            "type": ["info"],
            "action": raw.get("action") or "log_ingested",
            "outcome": raw.get("outcome") or "unknown",
        },
        "log": {"source": log_source},
        "service": {"name": service_name},
        "source": {"ip": source_ip},
        "labels": {
            "env": raw.get("env", "local"),
        },
    }

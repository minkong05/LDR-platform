import hashlib
import json
from datetime import datetime


def compute_dedupe_hash(
    *,
    log_source: str,
    service_name: str,
    source_ip: str,
    event_timestamp: datetime,
    raw: dict,
) -> str:
    """
    Stable dedupe hash so repeated deliveries don't create duplicates.
    Uses a canonical JSON encoding of key fields.
    """
    payload = {
        "log_source": log_source,
        "service_name": service_name,
        "source_ip": source_ip,
        "event_timestamp": event_timestamp.isoformat(),
        "raw": raw,
    }
    s = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

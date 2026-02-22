from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IngestEvent(BaseModel):
    """
    Minimal ingestion event from an agent.
    - `event_timestamp` is when the event happened at source.
    - `log_source` identifies the parser family (nginx/flask/docker).
    - `service_name` is the originating service.
    - `source_ip` supports first-pass investigation + indexing.
    - `raw` holds the original structured payload from the agent.
    """

    event_timestamp: datetime
    log_source: str = Field(min_length=1, max_length=32)
    service_name: str = Field(min_length=1, max_length=64)
    source_ip: str = Field(min_length=1, max_length=64)
    raw: dict[str, Any]


class IngestBatch(BaseModel):
    events: list[IngestEvent] = Field(min_length=1, max_length=500)

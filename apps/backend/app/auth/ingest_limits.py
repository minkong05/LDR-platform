from app.security.rate_limit import RateLimit, limiter
from fastapi import Header, HTTPException, status

INGEST_LIMIT = RateLimit(max_requests=60, window_seconds=60)  # 60 req/min per agent token


def rate_limit_ingest(x_agent_token: str | None = Header(default=None)) -> None:
    # Key by token (simple). Later we can key by token+ip or token+service.
    key = f"ingest:{x_agent_token or 'missing'}"

    if not limiter.allow(key, INGEST_LIMIT):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )

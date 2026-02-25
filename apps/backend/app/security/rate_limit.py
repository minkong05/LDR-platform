import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimit:
    max_requests: int
    window_seconds: int


class InMemoryRateLimiter:
    """
    Simple per-key sliding-window limiter.
    Good for local/demo. Later we can swap to Redis with same interface.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: RateLimit) -> bool:
        now = time.time()
        q = self._hits[key]

        # drop old timestamps
        while q and (now - q[0]) > limit.window_seconds:
            q.popleft()

        if len(q) >= limit.max_requests:
            return False

        q.append(now)
        return True


limiter = InMemoryRateLimiter()

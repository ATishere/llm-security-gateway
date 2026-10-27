from collections import defaultdict, deque
from time import monotonic


class InMemoryRateLimiter:
    """Single-process sliding-window limiter; use a shared store in production."""

    def __init__(self, limit: int = 60, window_seconds: int = 60) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("limit and window_seconds must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = monotonic()
        requests = self._requests[key]
        while requests and now - requests[0] >= self.window_seconds:
            requests.popleft()
        if len(requests) >= self.limit:
            return False
        requests.append(now)
        return True

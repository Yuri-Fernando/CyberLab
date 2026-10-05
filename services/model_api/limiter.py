"""Rate limiter em memória para laboratório; use storage distribuído em produção."""

from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class SlidingWindowRateLimiter:
    def __init__(self, limit=30, window_seconds=60.0):
        if limit < 1 or window_seconds <= 0:
            raise ValueError("limit e window_seconds devem ser positivos")
        self.limit = limit
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)
        self._lock = Lock()

    def allow(self, client_key):
        now = monotonic()
        with self._lock:
            events = self._events[client_key]
            while events and now - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True

    def count(self, client_key):
        with self._lock:
            return len(self._events[client_key])

"""Thread-safe sliding-window request rate limiter."""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """Permit a fixed number of requests during each rolling 60-second window."""

    _WINDOW_SECONDS = 60.0

    def __init__(self, requests_per_minute: int) -> None:
        if (
            isinstance(requests_per_minute, bool)
            or not isinstance(requests_per_minute, int)
            or requests_per_minute < 1
        ):
            raise ValueError("requests_per_minute must be a positive integer")
        self._limit = requests_per_minute
        self._requests: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Return whether another request fits in the current sliding window."""
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._WINDOW_SECONDS
            while self._requests and self._requests[0] <= cutoff:
                self._requests.popleft()
            if len(self._requests) >= self._limit:
                return False
            self._requests.append(now)
            return True
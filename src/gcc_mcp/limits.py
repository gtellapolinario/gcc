"""Runtime request-limiting helpers."""

from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Callable


class RateLimiter:
    """In-memory sliding-window limiter for MCP tool calls."""

    def __init__(
        self,
        limit_per_minute: int = 0,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self._lock = Lock()
        self._events: deque[float] = deque()
        self._now_fn = now_fn or time.monotonic
        self.limit_per_minute = max(0, int(limit_per_minute))

    def configure(self, limit_per_minute: int) -> None:
        """Update limit and clear previously tracked events."""
        with self._lock:
            self.limit_per_minute = max(0, int(limit_per_minute))
            self._events.clear()

    def allow(self) -> tuple[bool, int]:
        """Return whether request is allowed and retry-after in seconds."""
        with self._lock:
            if self.limit_per_minute <= 0:
                return True, 0

            now = self._now_fn()
            self._prune(now)
            if len(self._events) >= self.limit_per_minute:
                retry_after = max(1, int(60 - (now - self._events[0])))
                return False, retry_after

            self._events.append(now)
            return True, 0

    def _prune(self, now: float) -> None:
        while self._events and (now - self._events[0]) >= 60:
            self._events.popleft()

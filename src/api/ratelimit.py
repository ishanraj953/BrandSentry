#!/usr/bin/env python3
"""
BrandSentra - In-process sliding-window rate limiter.

Good enough for a single API process; put a reverse proxy limiter in front
when running several workers.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, Optional, Tuple

_RULE_RE = re.compile(r"^\s*(\d+)\s*/\s*(second|sec|s|minute|min|m|hour|hr|h|day|d)\s*$", re.I)
_UNIT_SECONDS = {
    "second": 1,
    "sec": 1,
    "s": 1,
    "minute": 60,
    "min": 60,
    "m": 60,
    "hour": 3600,
    "hr": 3600,
    "h": 3600,
    "day": 86400,
    "d": 86400,
}


def parse_rule(rule: Optional[str]) -> Optional[Tuple[int, int]]:
    """Parse ``"100/hour"`` into ``(limit, window_seconds)``; ``None`` disables."""
    if not rule:
        return None
    match = _RULE_RE.match(str(rule))
    if not match:
        raise ValueError(f"invalid rate limit rule {rule!r}; expected e.g. '100/hour'")
    limit = int(match.group(1))
    if limit <= 0:
        return None
    return limit, _UNIT_SECONDS[match.group(2).lower()]


class RateLimiter:
    """Sliding-window limiter keyed by an arbitrary string (usually the client IP)."""

    def __init__(self, rule: Optional[str] = "100/hour", now: Callable[[], float] = time.time):
        parsed = parse_rule(rule)
        self.enabled = parsed is not None
        self.limit, self.window = parsed if parsed else (0, 0)
        self._now = now
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> Tuple[bool, int, int]:
        """
        Register a hit for ``key``.

        Returns ``(allowed, remaining, retry_after_seconds)``.
        """
        if not self.enabled:
            return True, -1, 0
        now = self._now()
        cutoff = now - self.window
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry = int(bucket[0] + self.window - now) + 1
                return False, 0, max(retry, 1)
            bucket.append(now)
            remaining = self.limit - len(bucket)
            if len(self._hits) > 10000:
                self._purge(cutoff)
        return True, remaining, 0

    def _purge(self, cutoff: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            del self._hits[key]

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


__all__ = ["RateLimiter", "parse_rule"]

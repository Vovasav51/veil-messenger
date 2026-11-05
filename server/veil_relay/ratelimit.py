"""In-memory token-bucket rate limiting.

Limits are per-process (documented): the MVP relay is a single loopback process.
Buckets are keyed by an opaque scope+key pair; keys are UIDs or client IPs and
are never logged.
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .config import RateLimit


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._max_buckets = 20000

    def hit(self, scope: str, key: str, limit: RateLimit) -> int:
        """Consume one token. Returns 0 if allowed, else seconds to wait."""

        now = self._clock()
        refill_per_second = limit.per_minute / 60.0
        capacity = float(limit.burst)
        bucket_key = (scope, key)
        with self._lock:
            bucket = self._buckets.get(bucket_key)
            if bucket is None:
                bucket = _Bucket(tokens=capacity, updated=now)
                self._buckets[bucket_key] = bucket
                self._maybe_prune(now)
            else:
                elapsed = max(0.0, now - bucket.updated)
                bucket.tokens = min(capacity, bucket.tokens + elapsed * refill_per_second)
                bucket.updated = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return 0
            missing = 1.0 - bucket.tokens
            return max(1, math.ceil(missing / refill_per_second))

    def _maybe_prune(self, now: float) -> None:
        if len(self._buckets) < self._max_buckets:
            return
        stale = [key for key, bucket in self._buckets.items() if now - bucket.updated > 600]
        for key in stale:
            self._buckets.pop(key, None)
        if len(self._buckets) >= self._max_buckets:
            # Last resort: drop an arbitrary slice so memory stays bounded.
            for key in list(self._buckets)[: self._max_buckets // 4]:
                self._buckets.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._buckets.clear()

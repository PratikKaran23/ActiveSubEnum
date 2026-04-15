"""
core/rate_limiter.py — Token Bucket Rate Limiter (Part 7, Part 8)

Provides:
  RateLimiter — Token bucket rate limiter with per-resolver tracking
  GlobalRateLimiter — Shared limiter across all threads/coroutines

Used by stealth workflows and when --rate-limit is specified.
"""

import time
import threading
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class Bucket:
    """Token bucket for a single resolver or global use."""
    tokens: float
    last_refill: float
    rate: float  # tokens per second
    capacity: float  # max tokens

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens. Returns True if allowed, False if rate-limited.

        Uses a simple token bucket algorithm:
        - Refill tokens based on elapsed time since last check
        - If enough tokens available, consume and return True
        - Otherwise, return False (caller should sleep and retry)
        """
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate
        )
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    def wait_time(self, tokens: int = 1) -> float:
        """How many seconds until we can consume tokens?"""
        needed = tokens - self.tokens
        if needed <= 0:
            return 0.0
        return needed / self.rate


class RateLimiter:
    """Token bucket rate limiter with per-resolver tracking.

    Usage:
        limiter = RateLimiter(qps=5)  # 5 queries per second
        for resolver in resolvers:
            if not limiter.acquire(resolver):
                time.sleep(limiter.wait_time(resolver))
            # ... make query ...
    """

    def __init__(self, qps: float = 0, burst: float = 10):
        """
        Args:
            qps: Queries per second (total across all resolvers if per_resolver=False)
            burst: Bucket capacity — allows short bursts above qps
        """
        self.qps = qps
        self.burst = burst
        self._lock = threading.Lock()
        self._buckets: Dict[str, Bucket] = {}
        self._global = Bucket(
            tokens=burst,
            last_refill=time.time(),
            rate=qps,
            capacity=burst,
        )

    def acquire(self, key: str = "__global__", blocking: bool = False) -> bool:
        """Acquire a token for the given key.

        Args:
            key: Per-resolver key or "__global__" for shared bucket
            blocking: If True, sleep until token is available

        Returns:
            True if token acquired, False if blocked (non-blocking mode)
        """
        if self.qps <= 0:
            return True  # Unlimited

        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = Bucket(
                    tokens=self.burst,
                    last_refill=time.time(),
                    rate=self.qps,
                    capacity=self.burst,
                )
            bucket = self._buckets[key]

        if blocking:
            waited = 0.0
            while not bucket.consume(1):
                wait = bucket.wait_time(1)
                time.sleep(min(wait, 1.0))
                waited += wait
                if waited > 30:  # Max 30s wait
                    return False
            return True
        else:
            return bucket.consume(1)

    def wait_time(self, key: str = "__global__") -> float:
        """Return seconds until next token available."""
        if self.qps <= 0:
            return 0.0
        with self._lock:
            if key not in self._buckets:
                return 0.0
            return self._buckets[key].wait_time(1)

    def sleep_for_rate(self, key: str = "__global__", jitter: float = 0):
        """Sleep for the rate-limit delay, with optional jitter."""
        wait = self.wait_time(key)
        if jitter > 0:
            wait += (random.random() * jitter)
        if wait > 0:
            time.sleep(wait)


import random  # noqa: E402
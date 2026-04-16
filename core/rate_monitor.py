"""
core/rate_monitor.py — Rate Limit Detection and Auto-Backoff

Provides:
  RateLimitMonitor — Sliding-window failure rate tracking with
    automatic thread reduction, cooldown, and concurrent technique
    execution during brute-force pauses.

Usage:
  monitor = RateLimitMonitor(qps_threshold=0.3, severe_threshold=0.6)
  monitor.start(pool)

  # In brute force loop:
  monitor.record(query_time_ms, is_failure=bool(err))
  if monitor.should_backoff():
      monitor.apply_backoff(console, threads_ref)
      run_cooldown_techniques()

  monitor.stop()
"""

import threading
import time
from typing import Callable, Dict, List, Optional


class RateLimitMonitor:
    """Detects DNS rate limiting and applies automatic backoff.

    Tracks a sliding 60-second window of query results, per-resolver
    failure counts, and applies graduated backoff when failure rates
    exceed thresholds.

    Thresholds:
      >30% failures  → moderate backoff: 50% threads, 30s pause
      >60% failures  → severe backoff: 25% threads, 60s pause

    Gradual ramp-back: 25% → 50% → 75% → 100% over cooldown period.
    Per-resolver cooldown: 2 consecutive SERVFAILs → 60s remove → re-add.
    """

    def __init__(
        self,
        failure_threshold: float = 0.30,   # 30% failures → backoff
        severe_threshold: float = 0.60,     # 60% failures → severe
        cooldown_seconds: float = 30.0,
        severe_cooldown: float = 60.0,
    ):
        self.failure_threshold = failure_threshold
        self.severe_threshold = severe_threshold
        self.cooldown_seconds = cooldown_seconds
        self.severe_cooldown = severe_cooldown

        self._lock = threading.Lock()
        # Sliding window: (timestamp, is_failure, resolver_ip)
        self._events: List[tuple] = []
        self._window = 60.0                 # seconds

        # Per-resolver tracking: {ip: {"servfail": N, "timeout": N, "consec_fail": N, "cooldown_until": float}}
        self._resolver_stats: Dict[str, Dict] = {}

        self._in_backoff = False
        self._backoff_until = 0.0
        self._backoff_level = 0           # 0=none, 1=moderate, 2=severe
        self._backoff_count = 0
        self._queries_since_check = 0
        self._total_queries = 0
        self._total_failures = 0

        self._pool_ref = None              # ResolverPool reference
        self._stop = threading.Event()
        self._ramp_start = 0.0

    def set_pool(self, pool):
        """Attach the resolver pool for health reporting."""
        self._pool_ref = pool

    # ── Per-resolver tracking ─────────────────────────────────────────────────

    def _init_resolver(self, ip: str):
        if ip not in self._resolver_stats:
            self._resolver_stats[ip] = {
                "servfail": 0,
                "timeout": 0,
                "consec_fail": 0,
                "cooldown_until": 0.0,
            }

    def _cleanup_resolver_cooldowns(self):
        """Re-enable resolvers whose cooldown has expired."""
        now = time.time()
        for ip, stat in self._resolver_stats.items():
            if stat["cooldown_until"] > 0 and now >= stat["cooldown_until"]:
                stat["consec_fail"] = 0
                stat["cooldown_until"] = 0.0

    # ── Public API ─────────────────────────────────────────────────────────────

    def record_success(self, resolver_ip: str, latency_ms: float):
        """Record a successful query."""
        now = time.time()
        with self._lock:
            self._events.append((now, False, resolver_ip))
            self._total_queries += 1

            # Per-resolver: reset consec_fail
            self._init_resolver(resolver_ip)
            self._resolver_stats[resolver_ip]["consec_fail"] = 0

            # Prune old window
            cutoff = now - self._window
            self._events = [(t, f, r) for t, f, r in self._events if t > cutoff]
            self._queries_since_check += 1

    def record_failure(self, resolver_ip: str, reason: str):
        """Record a failed query.

        Args:
            resolver_ip: IP address of the resolver that failed
            reason: one of "SERVFAIL", "TIMEOUT", "NXDOMAIN", "REFUSED", "OTHER"
        """
        now = time.time()
        with self._lock:
            self._events.append((now, True, resolver_ip))
            self._total_queries += 1
            self._total_failures += 1

            # Per-resolver stats
            self._init_resolver(resolver_ip)
            stat = self._resolver_stats[resolver_ip]
            reason_upper = reason.upper()

            if reason_upper == "SERVFAIL":
                stat["servfail"] += 1
                stat["consec_fail"] += 1
            elif reason_upper == "TIMEOUT":
                stat["timeout"] += 1
                stat["consec_fail"] += 1
            else:
                stat["consec_fail"] += 1

            # Per-resolver cooldown: 2 consecutive fails → 60s cooldown
            if stat["consec_fail"] >= 2 and stat["cooldown_until"] == 0.0:
                stat["cooldown_until"] = now + 60.0

            # Prune old window
            cutoff = now - self._window
            self._events = [(t, f, r) for t, f, r in self._events if t > cutoff]
            self._queries_since_check += 1

    def is_rate_limited(self) -> bool:
        """Return True if currently in a backoff period, or if we should start one.

        Checks failure rate immediately so callers don't need to separately
        call should_backoff() to trigger the evaluation.
        """
        if self._in_backoff:
            if time.time() >= self._backoff_until:
                self._end_backoff()
                return False
            return True

        # Check failure rate immediately
        if self._queries_since_check >= 100:
            self._queries_since_check = 0
            rate = self._current_failure_rate()
            if rate >= self.severe_threshold:
                self._start_backoff(2)
                return True
            elif rate >= self.failure_threshold:
                self._start_backoff(1)
                return True

        return False

    def get_status(self) -> Dict:
        """Return current monitor state as a dict.

        Includes: failure_rate, total_queries, total_failures,
        backoff_level, backoff_remaining_s, per_resolver stats.
        """
        now = time.time()
        with self._lock:
            rate = self._current_failure_rate_unlocked()
            events_in_window = len(self._events)
            failures_in_window = sum(1 for _, f, _ in self._events if f)

        resolver_stats = {}
        with self._lock:
            for ip, stat in self._resolver_stats.items():
                cooldown = max(0.0, stat["cooldown_until"] - now) if stat["cooldown_until"] > now else 0.0
                resolver_stats[ip] = {
                    "servfail": stat["servfail"],
                    "timeout": stat["timeout"],
                    "consec_fail": stat["consec_fail"],
                    "cooldown_remaining": round(cooldown, 1),
                }

        return {
            "failure_rate": round(rate, 4),
            "queries_in_window": events_in_window,
            "failures_in_window": failures_in_window,
            "total_queries": self._total_queries,
            "total_failures": self._total_failures,
            "in_backoff": self._in_backoff,
            "backoff_level": self._backoff_level,
            "backoff_remaining_s": round(max(0.0, self._backoff_until - now), 1),
            "backoff_count": self._backoff_count,
            "per_resolver": resolver_stats,
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _current_failure_rate_unlocked(self) -> float:
        if not self._events:
            return 0.0
        failures = sum(1 for _, f, _ in self._events if f)
        return failures / len(self._events)

    def _current_failure_rate(self) -> float:
        with self._lock:
            return self._current_failure_rate_unlocked()

    def should_backoff(self) -> bool:
        """Check if we should start a backoff period."""
        if self._in_backoff:
            if time.time() >= self._backoff_until:
                self._end_backoff()
                return False
            return True

        self._cleanup_resolver_cooldowns()

        if self._queries_since_check < 100:
            return False

        self._queries_since_check = 0
        rate = self._current_failure_rate()

        if rate >= self.severe_threshold:
            self._start_backoff(2)
            return True
        elif rate >= self.failure_threshold:
            self._start_backoff(1)
            return True

        return False

    def _start_backoff(self, level: int):
        """Enter backoff mode."""
        self._in_backoff = True
        self._backoff_level = level
        self._backoff_count += 1
        self._ramp_start = time.time()

        if level == 2:
            self._backoff_until = time.time() + self.severe_cooldown
        else:
            self._backoff_until = time.time() + self.cooldown_seconds

    def _end_backoff(self):
        """End backoff and begin gradual ramp-up."""
        self._in_backoff = False
        self._backoff_level = 0

    def apply_backoff(self, console, threads_ref: list) -> Optional[str]:
        """Apply thread reduction. Returns message to print. Modifies threads_ref[0]."""
        if self._backoff_level == 0:
            return None

        current = threads_ref[0]

        if self._backoff_level == 2:
            # Severe: drop to 25%
            new_threads = max(10, int(current * 0.25))
            threads_ref[0] = new_threads
            return (f"[!] Severe rate limiting detected ({self._current_failure_rate():.0%} "
                    f"failure rate). Reducing threads {current} → {new_threads}. "
                    f"Pausing {self.severe_cooldown:.0f}s, running low-noise techniques.")

        elif self._backoff_level == 1:
            # Moderate: drop to 50%
            new_threads = max(25, int(current * 0.5))
            threads_ref[0] = new_threads
            return (f"[!] Rate limiting detected ({self._current_failure_rate():.0%} "
                    f"failure rate). Reducing threads {current} → {new_threads}. "
                    f"Backing off {self.cooldown_seconds:.0f}s.")

        return None

    def current_thread_multiplier(self) -> float:
        """Return the current thread multiplier for gradual ramp-up."""
        if not self._in_backoff or self._backoff_level == 0:
            return 1.0

        if self._backoff_level == 2:
            # Severe: slower ramp over 60s
            elapsed = time.time() - self._ramp_start
            ramps = [0.0, 15.0, 30.0, 45.0, 60.0]
            targets = [0.25, 0.25, 0.50, 0.75, 1.0]
        else:
            # Moderate: faster ramp over 30s
            elapsed = time.time() - self._ramp_start
            ramps = [0.0, 7.5, 15.0, 22.5, 30.0]
            targets = [0.50, 0.50, 0.75, 1.0, 1.0]

        for i in range(len(ramps) - 1):
            if ramps[i] <= elapsed < ramps[i + 1]:
                t = (elapsed - ramps[i]) / (ramps[i + 1] - ramps[i])
                return targets[i] + t * (targets[i + 1] - targets[i])

        return 1.0

    def is_in_backoff(self) -> bool:
        return self._in_backoff

    def backoff_remaining(self) -> float:
        """Seconds remaining in current backoff."""
        if not self._in_backoff:
            return 0.0
        return max(0.0, self._backoff_until - time.time())

    def is_severe(self) -> bool:
        return self._in_backoff and self._backoff_level == 2

    def summary(self) -> str:
        """Return a brief summary string for display."""
        rate = self._current_failure_rate()
        backoff_str = ""
        if self._in_backoff:
            remaining = self.backoff_remaining()
            lvl = "SEVERE" if self._backoff_level == 2 else "moderate"
            backoff_str = f" | BACKOFF({lvl}) {remaining:.0f}s"
        return f"Rate monitor: {rate:.0%} fail rate{backoff_str}"

    def get_brief(self) -> str:
        """Return a very brief one-liner for periodic status updates."""
        rate = self._current_failure_rate()
        if self._in_backoff:
            remaining = self.backoff_remaining()
            lvl = "SEVERE" if self._backoff_level == 2 else "moderate"
            return f"Rate: {rate:.0%} fail | BACKOFF({lvl}) {remaining:.0f}s"
        return f"Rate: {rate:.0%} fail"

    def start(self):
        """Start background health reporting thread — fires at most every 60s,
        and only when fail rate > 10% or actively in backoff."""
        def reporter():
            while not self._stop.is_set():
                time.sleep(60)
                if self._total_queries == 0 or self._stop.is_set():
                    continue
                rate = self._current_failure_rate()
                # Only print if fail rate > 10% or in backoff
                if rate > 0.10 or self._in_backoff:
                    print(f"  [*] {self.get_brief()}")
        self._thread = threading.Thread(target=reporter, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
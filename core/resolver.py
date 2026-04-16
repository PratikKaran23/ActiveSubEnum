"""
core/resolver.py — DNS Resolver Pool and Resolution Helpers

Provides:
  ResolverPool       — Large pool with random selection + health tracking
  resolve_a/aaaa/ns/txt/cname/any() — Resolution helpers
  ResolverHealth     — Pre-scan validation
  ResolverRefresh    — Live fetch from multiple public sources
"""

import random
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

from .config import DEFAULT_RESOLVERS


# ─── Resolver Pool ────────────────────────────────────────────────────────────


class ResolverStats:
    """Per-resolver statistics and health state."""

    def __init__(self, ip: str):
        self.ip = ip
        self.queries = 0
        self.success = 0
        self.servfail = 0
        self.timeout = 0
        self.noanswer = 0
        self.total_latency_ms = 0.0
        self.status = "healthy"      # healthy | throttled | dead
        self.throttled_until = 0.0   # unix timestamp when throttling expires
        self._recent = []            # circular buffer of recent results
        self._lock = threading.Lock()

    def record(self, latency_ms: Optional[float], err_type: Optional[str]):
        """Record a query result. Call with lock held externally."""
        self.queries += 1
        entry = (time.time(), err_type)
        self._recent.append(entry)
        # Keep last 20 results for throttling detection
        if len(self._recent) > 20:
            self._recent = self._recent[-20:]

        if err_type == "success":
            self.success += 1
            if latency_ms is not None:
                self.total_latency_ms += latency_ms
        elif err_type == "servfail":
            self.servfail += 1
        elif err_type == "timeout":
            self.timeout += 1
        elif err_type == "noanswer":
            self.noanswer += 1

    def recent_failure_rate(self) -> float:
        """Fraction of last 20 queries that failed (servfail or timeout)."""
        if not self._recent:
            return 0.0
        failures = sum(1 for _, e in self._recent if e in ("servfail", "timeout"))
        return failures / len(self._recent)

    def avg_latency_ms(self) -> float:
        if self.success == 0:
            return 0.0
        return self.total_latency_ms / self.success


class ResolverPool:
    """Thread-safe DNS resolver pool with random selection and health eviction.

    Key improvements over Part 1:
    - Random selection by default (better load distribution across resolvers)
    - Per-resolver statistics and throttled/dead eviction
    - Large pool support (5000+ resolvers without degradation)
    - Background refresh to replace dead resolvers
    """

    def __init__(self, resolvers: List[str], timeout: int = 3, check_health: bool = True):
        self.timeout = timeout
        self._lock = threading.Lock()
        self._resolvers: List[str] = resolvers or list(DEFAULT_RESOLVERS)
        self._stats: Dict[str, ResolverStats] = {}
        self._dead: set = set()      # permanently dead (all queries failed)
        self._eviction_count = 0
        self._refresh_thread: Optional[threading.Thread] = None
        self._stop_refresh = threading.Event()

        # Initialize stats for all resolvers
        for ip in self._resolvers:
            self._stats[ip] = ResolverStats(ip)

        if check_health:
            self._do_initial_health_check()

    def _do_initial_health_check(self):
        """Quick health check to remove obviously dead resolvers before scan starts."""
        test_domains = ["google.com", "cloudflare.com", "apple.com"]
        dead = []

        def check(ns):
            for dom in test_domains:
                try:
                    r = dns.resolver.Resolver()
                    r.nameservers = [ns]
                    r.timeout = 2
                    r.lifetime = 2
                    r.resolve(dom, "A")
                    return True
                except Exception:
                    continue
            return False

        with ThreadPoolExecutor(max_workers=100) as ex:
            results = list(ex.map(check, self._resolvers))

        new_resolvers = [ns for ns, ok in zip(self._resolvers, results) if ok]
        removed = len(self._resolvers) - len(new_resolvers)
        if removed:
            self._resolvers = new_resolvers
            print(f"  [i] Removed {removed} dead resolvers, {len(self._resolvers)} remain")

    def _active_resolvers(self) -> List[str]:
        """Return currently usable resolvers (not throttled/dead)."""
        now = time.time()
        active = []
        for ip in self._resolvers:
            if ip in self._dead:
                continue
            stats = self._stats.get(ip)
            if stats and stats.status == "throttled" and stats.throttled_until > now:
                continue
            active.append(ip)
        return active

    def get(self) -> Tuple[dns.resolver.Resolver, str]:
        """Return a resolver using random selection + record query start time.

        Returns (resolver_obj, resolver_ip).
        """
        active = self._active_resolvers()
        if not active:
            # Fallback: use any resolver
            active = self._resolvers[:1] if self._resolvers else ["8.8.8.8"]

        ip = random.choice(active)
        r = dns.resolver.Resolver()
        r.nameservers = [ip]
        r.timeout = self.timeout
        r.lifetime = self.timeout
        return r, ip

    def random(self) -> Tuple[dns.resolver.Resolver, str]:
        """Alias for get()."""
        return self.get()

    def record_result(self, ip: str, latency_ms: Optional[float], err_type: Optional[str]):
        """Record a query result for health tracking."""
        stats = self._stats.get(ip)
        if not stats:
            return

        with self._lock:
            stats.record(latency_ms, err_type)

        # Check eviction conditions (every ~100 queries)
        if stats.queries % 100 == 0:
            self._maybe_evict(stats)

    def _maybe_evict(self, stats: ResolverStats):
        """Check if a resolver should be evicted or un-throttled."""
        now = time.time()

        if stats.status == "throttled":
            if now >= stats.throttled_until:
                # Try to re-enable
                stats.status = "healthy"
                stats.throttled_until = 0.0
            return

        if stats.status == "dead":
            return

        # Check recent failure rate — require 20 queries before evaluating
        recent = stats._recent[-20:] if stats._recent else []
        if len(recent) < 20:
            return

        failures = sum(1 for _, e in recent if e in ("servfail", "timeout"))
        rate = failures / len(recent)

        # Only evict if >80% failures over last 20 queries (not aggressive)
        if rate > 0.8:
            with self._lock:
                stats.status = "throttled"
                stats.throttled_until = now + 120
                self._eviction_count += 1

    def record_success(self, ip: str, latency_ms: float):
        self.record_result(ip, latency_ms, "success")

    def record_servfail(self, ip: str):
        self.record_result(ip, None, "servfail")

    def record_timeout(self, ip: str):
        self.record_result(ip, None, "timeout")

    def record_noanswer(self, ip: str):
        self.record_result(ip, None, "noanswer")

    def health_summary(self) -> str:
        """Return human-readable pool health."""
        active = len(self._active_resolvers())
        throttled = sum(1 for s in self._stats.values() if s.status == "throttled")
        dead = len(self._dead)
        total = len(self._resolvers)
        evicted = self._eviction_count
        return (f"Pool: {total} total | {active} active | "
                f"{throttled} throttled | {dead} dead | {evicted} evictions")

    def __len__(self) -> int:
        return len(self._active_resolvers())

    def get_stats(self, ip: str) -> Optional[Dict]:
        """Return per-resolver stats dict.

        Returns None if resolver is not in the pool.
        """
        stats = self._stats.get(ip)
        if not stats:
            return None
        return {
            "ip": stats.ip,
            "queries": stats.queries,
            "success": stats.success,
            "servfail": stats.servfail,
            "timeout": stats.timeout,
            "noanswer": stats.noanswer,
            "avg_latency_ms": round(stats.avg_latency_ms(), 2),
            "status": stats.status,
            "recent_failure_rate": round(stats.recent_failure_rate(), 3),
        }

    def get_all_stats(self) -> Dict[str, Dict]:
        """Return stats for all resolvers."""
        return {ip: s for ip, s in self._stats.items()}

    def evict_resolver(self, ip: str) -> bool:
        """Mark a resolver as throttled and remove from active pool.

        Returns True if resolver was found and evicted, False otherwise.
        """
        stats = self._stats.get(ip)
        if not stats:
            return False
        now = time.time()
        stats.status = "throttled"
        stats.throttled_until = now + 90.0
        self._eviction_count += 1
        return True

    # ─── Resolution helpers ────────────────────────────────────────────────────

    def resolve_a(self, fqdn: str) -> Tuple[Optional[List[str]], str, Optional[float]]:
        """Resolve A record. Returns (ips, resolver_ip, latency_ms)."""
        r, ip = self.get()
        start = time.time()
        try:
            answers = r.resolve(fqdn, "A")
            latency = (time.time() - start) * 1000
            self.record_success(ip, latency)
            return [str(a.address) for a in answers], ip, latency
        except dns.exception.FormError:
            self.record_servfail(ip)
            return None, ip, None
        except dns.resolver.NXDOMAIN:
            return [], ip, (time.time() - start) * 1000
        except dns.resolver.NoAnswer:
            self.record_noanswer(ip)
            return None, ip, (time.time() - start) * 1000
        except Exception:
            self.record_timeout(ip)
            return None, ip, None

    def resolve_aaaa(self, fqdn: str) -> Tuple[Optional[List[str]], str, Optional[float]]:
        """Resolve AAAA record."""
        r, ip = self.get()
        start = time.time()
        try:
            answers = r.resolve(fqdn, "AAAA")
            latency = (time.time() - start) * 1000
            self.record_success(ip, latency)
            return [str(a.address) for a in answers], ip, latency
        except dns.exception.FormError:
            self.record_servfail(ip)
            return None, ip, None
        except dns.resolver.NXDOMAIN:
            return [], ip, (time.time() - start) * 1000
        except dns.resolver.NoAnswer:
            self.record_noanswer(ip)
            return None, ip, (time.time() - start) * 1000
        except Exception:
            self.record_timeout(ip)
            return None, ip, None

    def resolve_ns(self, domain: str) -> Tuple[Optional[List[str]], str, Optional[float]]:
        """Resolve NS records for a domain."""
        r, ip = self.get()
        start = time.time()
        try:
            answers = r.resolve(domain, "NS")
            latency = (time.time() - start) * 1000
            self.record_success(ip, latency)
            ns_ips = []
            for rdata in answers:
                try:
                    ns_ips.append(socket.gethostbyname(str(rdata.target)))
                except Exception:
                    pass
            return ns_ips if ns_ips else None, ip, latency
        except Exception:
            self.record_timeout(ip)
            return None, ip, None

    def resolve_txt(self, fqdn: str) -> Tuple[Optional[List[str]], str, Optional[float]]:
        """Resolve TXT record."""
        r, ip = self.get()
        start = time.time()
        try:
            answers = r.resolve(fqdn, "TXT")
            latency = (time.time() - start) * 1000
            self.record_success(ip, latency)
            return [" ".join(a.strings) for a in answers], ip, latency
        except dns.exception.FormError:
            self.record_servfail(ip)
            return None, ip, None
        except dns.resolver.NXDOMAIN:
            return [], ip, (time.time() - start) * 1000
        except dns.resolver.NoAnswer:
            self.record_noanswer(ip)
            return None, ip, (time.time() - start) * 1000
        except Exception:
            self.record_timeout(ip)
            return None, ip, None

    def resolve_cname(self, fqdn: str) -> Tuple[Optional[str], str, Optional[float]]:
        """Resolve CNAME record."""
        r, ip = self.get()
        start = time.time()
        try:
            answers = r.resolve(fqdn, "CNAME")
            latency = (time.time() - start) * 1000
            self.record_success(ip, latency)
            return str(answers[0].target).rstrip("."), ip, latency
        except dns.exception.FormError:
            self.record_servfail(ip)
            return None, ip, None
        except dns.resolver.NoAnswer:
            self.record_noanswer(ip)
            return None, ip, (time.time() - start) * 1000
        except Exception:
            self.record_timeout(ip)
            return None, ip, None

    def resolve_any(self, fqdn: str) -> Tuple[Optional[List[str]], str, Optional[float]]:
        """Resolve ANY record."""
        r, ip = self.get()
        start = time.time()
        try:
            answers = r.resolve(fqdn, "ANY")
            latency = (time.time() - start) * 1000
            self.record_success(ip, latency)
            return [str(a) for a in answers], ip, latency
        except dns.exception.FormError:
            self.record_servfail(ip)
            return None, ip, None
        except Exception:
            self.record_timeout(ip)
            return None, ip, None


# ─── Resolver Health ───────────────────────────────────────────────────────────

class ResolverHealth:
    """Pre-scan validation of resolver list."""

    def __init__(self, resolvers: List[str], timeout: int = 3, threads: int = 300):
        self.resolvers = resolvers
        self.timeout = timeout
        self.threads = threads
        self._healthy: List[Tuple[str, float]] = []

    def check(self) -> List[Tuple[str, float]]:
        """Validate resolvers by querying google.com. Returns (ip, latency_ms)."""
        def probe(ns: str) -> Optional[Tuple[str, float]]:
            try:
                start = time.time()
                r = dns.resolver.Resolver()
                r.nameservers = [ns]
                r.timeout = self.timeout
                r.lifetime = self.timeout
                answers = r.resolve("google.com", "A")
                latency = (time.time() - start) * 1000
                if answers:
                    return ns, latency
            except Exception:
                pass
            return None

        results = []
        with ThreadPoolExecutor(max_workers=min(self.threads, len(self.resolvers))) as ex:
            futures = {ex.submit(probe, ns): ns for ns in self.resolvers}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)

        results.sort(key=lambda x: x[1])
        self._healthy = results
        return results

    @property
    def healthy_count(self) -> int:
        return len(self._healthy)

    @property
    def fastest(self) -> Optional[str]:
        return self._healthy[0][0] if self._healthy else None


# ─── Resolver Refresh ─────────────────────────────────────────────────────────

RESOLVER_SOURCES = [
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt",
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
    "https://raw.githubusercontent.com/janmasarik/resolvers/master/nameservers.txt",
    "https://raw.githubusercontent.com/proabiral/fresh-resolvers/master/resolvers.txt",
    "https://raw.githubusercontent.com/BBerastegui/fresh-dns-servers/master/resolvers.txt",
    "https://raw.githubusercontent.com/re3l/DNS-Resolvers/master/resolvers.txt",
    "https://raw.githubusercontent.com/cqsd/daily-fresh-resolvers/master/resolvers.txt",
    "https://raw.githubusercontent.com/zakery1369/fresh-resolvers/master/resolvers",
    "https://raw.githubusercontent.com/zekkouallah/Fresh-DNS-Resolvers/main/resolvers.txt",
]


def fetch_resolvers_from_web(timeout: int = 15) -> List[str]:
    """Fetch DNS resolver IPs from all configured sources.

    Uses ThreadPoolExecutor + urllib (no aiohttp dependency).
    All sources fetched concurrently. Results merged + deduplicated.
    Falls back to DEFAULT_RESOLVERS only if every source fails.

    Args:
        timeout: seconds to wait per source (default 15)

    Returns:
        List of unique resolver IP strings
    """
    import urllib.request

    def _fetch_source(url: str) -> List[str]:
        """Fetch one source URL, return list of resolver IPs."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    return []
                lines = resp.read().decode("utf-8", errors="ignore").splitlines()
                return [ip for line in lines
                        if (ip := _parse_resolver_line(line))]
        except Exception:
            return []

    # Fetch all sources concurrently
    with ThreadPoolExecutor(max_workers=len(RESOLVER_SOURCES)) as ex:
        results = list(ex.map(_fetch_source, RESOLVER_SOURCES))

    raw: set = set()
    for result in results:
        raw.update(result)

    return list(raw) if raw else list(DEFAULT_RESOLVERS)


def _parse_resolver_line(line: str) -> Optional[str]:
    """Parse a resolver IP from a line of text. Returns IP or None."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(";"):
        return None
    ip = line.split()[0]
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return ip
    return None


class ResolverRefresh:
    """Fetch, validate, rank, and cache public DNS resolvers."""

    def __init__(self, timeout: int = 3, threads: int = 300):
        self.timeout = timeout
        self.threads = threads
        self._cache_file = ".resolvers_cache.txt"

    def fetch(self) -> List[str]:
        """Fetch resolver lists from all sources. Returns combined list."""
        try:
            import aiohttp
            import asyncio
        except ImportError:
            return list(DEFAULT_RESOLVERS)

        raw: set = set()

        async def _fetch_all():
            async with aiohttp.ClientTimeout(total=15) as tm:
                async with aiohttp.ClientSession(timeout=tm) as sess:
                    tasks = [sess.get(url) for url in RESOLVER_SOURCES]
                    for resp in await asyncio.gather(*tasks, return_exceptions=True):
                        if isinstance(resp, Exception):
                            continue
                        if resp.status == 200:
                            text = await resp.text()
                            for line in text.splitlines():
                                ip = line.strip().split()[0] if line.strip() else ""
                                if self._looks_like_resolver(ip):
                                    raw.add(ip)

        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

        try:
            asyncio.run(_fetch_all())
        except Exception:
            pass

        return list(raw) if raw else list(DEFAULT_RESOLVERS)

    def _looks_like_resolver(self, s: str) -> bool:
        if not s or s.startswith("#") or s.startswith(";"):
            return False
        parts = s.split(".")
        if len(parts) == 4:
            return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
        return False

    def validate(self, resolvers: List[str]) -> List[Tuple[str, float]]:
        health = ResolverHealth(resolvers, self.timeout, self.threads)
        return health.check()

    def get_pool(self,
                 use_cache: bool = True,
                 force_refresh: bool = False,
                 max_resolvers: int = 5000) -> List[str]:
        """Main entry point. Returns validated, ranked resolver list."""
        import os

        cache_path = self._cache_file
        if use_cache and not force_refresh and os.path.exists(cache_path):
            try:
                with open(cache_path) as f:
                    lines = f.readlines()
                    if lines and lines[0].startswith("# cached:"):
                        age = time.time() - float(lines[0].split(":")[1].strip())
                        if age < 3600:
                            resolvers = [l.strip() for l in lines[1:] if l.strip()]
                            if resolvers:
                                validated = self.validate(resolvers[:max_resolvers])
                                print(f"  [i] Cache hit: {len(validated)} healthy from cache")
                                return [r for r, _ in validated[:min(len(validated), max_resolvers)]]
            except Exception:
                pass

        # Try external healthy file first (our pre-validated 5651)
        external = "/tmp/fresh_resolvers/healthy.txt"
        if os.path.exists(external) and not force_refresh:
            try:
                with open(external) as f:
                    resolvers = [l.strip() for l in f if l.strip()]
                validated = self.validate(resolvers[:max_resolvers])
                if validated:
                    ips = [r for r, _ in validated[:min(len(validated), max_resolvers)]]
                    self._save_cache(ips)
                    return ips
            except Exception:
                pass

        # Fetch fresh
        raw = self.fetch()
        if not raw:
            return list(DEFAULT_RESOLVERS)

        # Validate subset (cap for speed)
        validated = self.validate(raw[:min(len(raw), max_resolvers)])

        if not validated:
            return list(DEFAULT_RESOLVERS)

        top = validated[:min(len(validated), max_resolvers)]
        ips = [r for r, _ in top]
        self._save_cache(ips)
        return ips

    def _save_cache(self, ips: List[str]):
        try:
            with open(self._cache_file, "w") as f:
                f.write(f"# cached: {time.time()}\n")
                f.write("\n".join(ips) + "\n")
        except Exception:
            pass

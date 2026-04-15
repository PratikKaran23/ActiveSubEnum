#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          ActiveSubEnum v1.0 — Active Subdomain Enumerator       ║
║          Beyond the standard playbook. Built for hunters.       ║
╚══════════════════════════════════════════════════════════════════╝

12 Active Techniques:
  [01] DNS Brute Force          — threaded, wildcard-aware
  [02] Permutation Engine       — mutation from known subs
  [03] Zone Transfer            — AXFR/IXFR against all NS
  [04] DNSSEC NSEC Walking      — provably complete if NSEC
  [05] DNS Cache Snooping       — non-recursive TTL analysis
  [06] IPv6 AAAA Enumeration    — the 95% blind spot
  [07] TLS SNI Probing          — bypass DNS via IP ranges
  [08] CAA Record Pivoting      — confirm existence via CAA
  [09] CORS Origin Reflection   — HTTP-layer trust mining
  [10] DNS CHAOS Class          — version/hostname leaks
  [11] VHost Fuzzing            — Host-header based discovery
  [12] Recursive Enumeration    — seeds discovered subs deeper
"""

import argparse
import asyncio
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ─── Dependency checks ───────────────────────────────────────────────────────

def check_deps():
    missing = []
    try:
        import dns.resolver  # noqa
    except ImportError:
        missing.append("dnspython")
    try:
        import aiohttp  # noqa
    except ImportError:
        missing.append("aiohttp")
    try:
        import rich  # noqa
    except ImportError:
        missing.append("rich")
    if missing:
        print(f"[!] Missing: {', '.join(missing)}")
        print(f"    Install: pip install {' '.join(missing)}")
        sys.exit(1)

check_deps()

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.zone

import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

console = Console()

# ─── Constants ───────────────────────────────────────────────────────────────

BANNER = """[bold cyan]
 ▄▄▄       ▄████▄  ▄▄▄█████▓ ██▓ ██▒   █▓▓█████
▒████▄    ▒██▀ ▀█  ▓  ██▒ ▓▒▓██▒▓██░   █▒▓█   ▀
▒██  ▀█▄  ▒▓█    ▄ ▒ ▓██░ ▒░▒██▒ ▓██  █▒░▒███
░██▄▄▄▄██ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ░██░  ▒██ █░░▒▓█  ▄
 ▓█   ▓██▒▒ ▓███▀ ░  ▒██▒ ░ ░██░   ▒▀█░  ░▒████▒
 ▒▒   ▓▒█░░ ░▒ ▒  ░  ▒ ░░   ░▓     ░ ▐░  ░░ ▒░ ░
  ▒   ▒▒ ░  ░  ▒       ░     ▒ ░   ░ ░░   ░ ░  ░
  ░   ▒   ░          ░       ▒ ░     ░░     ░
      ░  ░░ ░                ░        ░     ░  ░[/bold cyan]
[bold yellow]       SubEnum v1.0 — Active Only — 12 Techniques[/bold yellow]
[dim]       Beyond wordlists. Beyond CT logs. Beyond passive.[/dim]
"""

DEFAULT_RESOLVERS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222",
    "208.67.220.220", "64.6.64.6", "64.6.65.6",
]

BUILTIN_WORDLIST = [
    # Common services
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3", "ns4",
    "webmail", "remote", "blog", "server", "portal", "admin", "secure",
    # Dev/staging
    "dev", "staging", "stage", "test", "qa", "uat", "sit", "perf", "sandbox",
    "prod", "production", "beta", "alpha", "demo", "preview", "review",
    # APIs & apps
    "api", "api2", "api3", "v1", "v2", "v3", "app", "apps", "application",
    "mobile", "m", "web", "ws", "websocket", "socket", "stream", "grpc", "graphql",
    # Auth & identity
    "auth", "login", "sso", "oauth", "id", "identity", "ldap", "ad",
    "iam", "idp", "saml",
    # Infrastructure
    "vpn", "cdn", "static", "assets", "media", "img", "images",
    "upload", "downloads", "files", "backup", "bak", "dr",
    # Internal tools
    "intranet", "internal", "corp", "corporate", "extranet",
    "git", "gitlab", "github", "svn", "jira", "confluence",
    "jenkins", "ci", "cd", "build", "deploy",
    "docker", "k8s", "kubernetes", "consul", "vault",
    # Monitoring
    "prometheus", "grafana", "kibana", "elastic", "logstash",
    "sentry", "datadog", "newrelic", "splunk", "monitor", "status",
    # Databases
    "db", "database", "redis", "mongo", "mysql", "postgres",
    "oracle", "mssql", "cassandra",
    # Regions
    "eu", "us", "uk", "ap", "sg", "de", "fr", "in", "au",
    "east", "west", "north", "south", "central",
    "us-east", "us-west", "eu-west", "ap-southeast",
    # Business
    "shop", "store", "pay", "payment", "payments", "checkout", "billing",
    "invoice", "crm", "erp", "hrm",
    # Dashboards
    "dashboard", "panel", "management", "manage", "control", "admin2",
    "cpanel", "whm", "plesk", "webmin",
    # Comms
    "chat", "slack", "teams", "meet", "video", "conference",
    # Search
    "search", "autocomplete", "suggest", "elastic",
    # Numbers
    "1", "2", "3", "01", "02", "03",
    "www2", "mail2", "ns5", "ns6",
    # Cloud
    "aws", "gcp", "azure", "cloud", "edge", "lambda",
    # Analytics
    "analytics", "data", "bi", "reporting", "metrics", "log", "logs",
    # Misc
    "help", "support", "docs", "wiki", "kb", "faq",
    "old", "new", "legacy", "archive",
    "relay", "bounce", "mx1", "mx2",
]

PERMUTATION_PREFIXES = [
    "dev", "staging", "stage", "prod", "test", "qa", "uat",
    "api", "v1", "v2", "v3", "old", "new", "beta", "alpha",
    "internal", "corp", "admin", "secure", "backup", "bak",
    "eu", "us", "uk", "ap", "sg", "de", "fr",
    "east", "west", "north", "south",
    "01", "02", "1", "2", "2024", "2025",
]

PERMUTATION_SEPARATORS = ["-", ".", ""]

RECURSIVE_SEEDS = [
    "api", "dev", "staging", "internal", "admin", "test",
    "app", "v1", "v2", "service", "backend", "frontend",
    "auth", "login", "portal", "dashboard", "management",
    "data", "prod", "qa", "old", "new",
]

CHAOS_QUERIES = [
    "version.bind", "version.server", "hostname.bind",
    "id.server", "authors.bind", "build.bind",
]

# ─── Config ──────────────────────────────────────────────────────────────────

@dataclass
class Config:
    domain: str
    wordlist_path: str = ""
    resolvers: List[str] = field(default_factory=lambda: list(DEFAULT_RESOLVERS))
    threads: int = 100
    timeout: int = 3
    techniques: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    output: str = ""
    depth: int = 2
    api_endpoint: str = ""
    verbose: bool = False
    ports: List[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    dry_run: bool = False
    vhost_max_words: int = 400
    vhost_max_ips: int = 5
    # Part 7: output format
    output_format: str = "auto"  # auto, json, txt, csv, md
    # Part 7: skip http probe
    skip_http_probe: bool = False
    # Part 7: rate limit
    rate_limit: int = 0  # queries per second, 0 = unlimited
    # Part 7: sort by
    sort_by: str = "score"  # score, alpha, ip, technique
    # Part 7: opsec mode
    opsec_mode: bool = False
    # Part 8: refresh resolvers
    refresh_resolvers: bool = False
    # Part 7: resume
    resume: bool = False
    resume_file: str = ""
    # Part 7: skip wordlist cleaning
    skip_clean: bool = False
    # Part 7: permutation wordlist
    permutation_wordlist: str = ""
    # Part 7: annotate mode
    annotate: bool = False
    # Part 10: HTTP probe timeout
    http_timeout: int = 5
    # Rate limit & performance
    max_rate: int = 0       # hard cap queries/second across all threads
    jitter: int = 0         # random delay (ms) per query per thread
    shuffle: bool = False   # randomize wordlist order
    resolvers_file: str = ""  # explicit resolver file

# ─── Result Collector ────────────────────────────────────────────────────────

class ResultCollector:
    """Thread-safe, deduplicated result store."""

    def __init__(self, verbose: bool = False):
        self.found: Dict[str, Dict] = {}
        self._lock = asyncio.Lock()
        self._sync_lock = __import__("threading").Lock()
        self.verbose = verbose

    def _clean(self, sub: str) -> str:
        return sub.lower().rstrip(".").strip()

    def _emit(self, sub: str, ips: List[str], technique: str):
        console.print(
            f"  [bold green][+][/bold green] [cyan]{sub}[/cyan]"
            f"  [dim]→[/dim]  [yellow]{', '.join(ips[:3])}[/yellow]"
            f"  [dim]({technique})[/dim]"
        )

    def add_sync(self, sub: str, ips: List[str], technique: str) -> bool:
        sub = self._clean(sub)
        if not sub:
            return False
        with self._sync_lock:
            if sub not in self.found:
                self.found[sub] = {"ips": ips, "techniques": [technique]}
                self._emit(sub, ips, technique)
                return True
            else:
                if technique not in self.found[sub]["techniques"]:
                    self.found[sub]["techniques"].append(technique)
                return False

    async def add(self, sub: str, ips: List[str], technique: str) -> bool:
        sub = self._clean(sub)
        if not sub:
            return False
        async with self._lock:
            if sub not in self.found:
                self.found[sub] = {"ips": ips, "techniques": [technique]}
                self._emit(sub, ips, technique)
                return True
            else:
                if technique not in self.found[sub]["techniques"]:
                    self.found[sub]["techniques"].append(technique)
                return False

    def all_subs(self) -> Set[str]:
        return set(self.found.keys())

# ─── Resolver Pool ───────────────────────────────────────────────────────────
import threading

class ResolverStats:
    """Per-resolver statistics and health state."""

    def __init__(self, ip: str):
        self.ip = ip
        self.queries = 0
        self.success = 0
        self.servfail = 0
        self.timeout = 0
        self.total_latency_ms = 0.0
        self.status = "healthy"
        self.throttled_until = 0.0
        self._recent = []
        self._lock = threading.Lock()

    def record(self, latency_ms: Optional[float], err_type: Optional[str]):
        with self._lock:
            self.queries += 1
            entry = (time.time(), err_type)
            self._recent.append(entry)
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

    def recent_failure_rate(self) -> float:
        if not self._recent:
            return 0.0
        failures = sum(1 for _, e in self._recent if e in ("servfail", "timeout"))
        return failures / len(self._recent)


class ResolverPool:
    """Thread-safe DNS resolver pool with random selection and health eviction.

    Key improvements:
    - Random selection by default (better load distribution)
    - Per-resolver statistics and throttled/dead eviction
    - Large pool support (5000+ resolvers)
    """

    def __init__(self, resolvers: List[str], timeout: int = 3,
                 track_health: bool = True, do_health_check: bool = True):
        self.timeout = timeout
        self._lock = threading.Lock()
        self._resolvers: List[str] = resolvers or list(DEFAULT_RESOLVERS)
        self._stats: Dict[str, ResolverStats] = {}
        self._dead: set = set()
        self._eviction_count = 0
        self._health_check_done = False
        self._last_result_type: Optional[str] = None  # "success" | "nxdomain" | "noanswer" | "timeout" | "servfail"
        self._last_ip: Optional[str] = None  # IP of last resolver used (for rate monitor)

        for ip in self._resolvers:
            self._stats[ip] = ResolverStats(ip)

        if do_health_check and track_health:
            self._do_health_check()

    def _do_health_check(self):
        """Quick health check to remove dead resolvers."""
        if self._health_check_done:
            return
        self._health_check_done = True
        test_ds = ["google.com", "cloudflare.com", "apple.com"]

        def check(ns):
            for dom in test_ds:
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

        with ThreadPoolExecutor(max_workers=min(100, len(self._resolvers))) as ex:
            results = list(ex.map(check, self._resolvers))

        new_res = [ns for ns, ok in zip(self._resolvers, results) if ok]
        removed = len(self._resolvers) - len(new_res)
        if removed:
            self._resolvers = new_res
            print(f"  [i] Removed {removed} dead resolvers, {len(self._resolvers)} healthy")

    def _active(self) -> List[str]:
        now = time.time()
        active = []
        for ip in self._resolvers:
            if ip in self._dead:
                continue
            stats = self._stats.get(ip)
            if stats and stats.status == "throttled" and stats.throttled_until > now:
                continue
            active.append(ip)
        return active or self._resolvers[:1]

    def get(self) -> Tuple[dns.resolver.Resolver, str]:
        """Return (resolver, resolver_ip) using random selection."""
        active = self._active()
        ip = random.choice(active) if active else self._resolvers[0]
        self._last_ip = ip
        r = dns.resolver.Resolver()
        r.nameservers = [ip]
        r.timeout = self.timeout
        r.lifetime = self.timeout
        return r, ip

    def random(self) -> Tuple[dns.resolver.Resolver, str]:
        return self.get()

    def record_result(self, ip: str, latency_ms: Optional[float],
                      err_type: Optional[str]):
        with self._lock:
            self._last_result_type = err_type
        stats = self._stats.get(ip)
        if not stats:
            return
        stats.record(latency_ms, err_type)
        if stats.queries % 100 == 0:
            self._maybe_evict(stats)

    def _maybe_evict(self, stats: ResolverStats):
        now = time.time()
        if stats.status == "throttled":
            if now >= stats.throttled_until:
                stats.status = "healthy"
                stats.throttled_until = 0.0
            return
        if stats.status == "dead":
            return
        recent = stats._recent[-20:] if stats._recent else []
        if len(recent) < 5:
            return
        timeouts = sum(1 for _, e in recent if e == "timeout")
        if timeouts >= 8:
            with self._lock:
                stats.status = "dead"
                self._dead.add(stats.ip)
                self._eviction_count += 1
            return
        rate = stats.recent_failure_rate()
        if rate > 0.5:
            with self._lock:
                stats.status = "throttled"
                stats.throttled_until = now + 90
                self._eviction_count += 1

    def record_success(self, ip: str, latency_ms: float):
        self.record_result(ip, latency_ms, "success")

    def record_servfail(self, ip: str):
        self.record_result(ip, None, "servfail")

    def record_timeout(self, ip: str):
        self.record_result(ip, None, "timeout")

    def health_summary(self) -> str:
        active = len(self._active())
        throttled = sum(1 for s in self._stats.values() if s.status == "throttled")
        dead = len(self._dead)
        return (f"Pool: {len(self._resolvers)} total | {active} active | "
                f"{throttled} throttled | {dead} dead")

    def __len__(self) -> int:
        return len(self._active())


def resolve_a(fqdn: str, pool: ResolverPool) -> Optional[List[str]]:
    r, ip = pool.get()
    start = time.time()
    try:
        answers = r.resolve(fqdn, "A")
        latency = (time.time() - start) * 1000
        pool.record_success(ip, latency)
        return [str(a.address) for a in answers]
    except dns.exception.FormError:
        pool.record_servfail(ip)
        return None
    except dns.resolver.NXDOMAIN:
        latency = (time.time() - start) * 1000
        pool.record_result(ip, latency, "nxdomain")
        return []
    except dns.resolver.NoAnswer:
        pool.record_result(ip, (time.time() - start) * 1000, "noanswer")
        return None
    except Exception:
        pool.record_timeout(ip)
        return None


def resolve_aaaa(fqdn: str, pool: ResolverPool) -> Optional[List[str]]:
    r, ip = pool.get()
    start = time.time()
    try:
        answers = r.resolve(fqdn, "AAAA")
        latency = (time.time() - start) * 1000
        pool.record_success(ip, latency)
        return [str(a.address) for a in answers]
    except dns.exception.FormError:
        pool.record_servfail(ip)
        return None
    except dns.resolver.NXDOMAIN:
        latency = (time.time() - start) * 1000
        pool.record_result(ip, latency, "nxdomain")
        return []
    except dns.resolver.NoAnswer:
        pool.record_result(ip, (time.time() - start) * 1000, "noanswer")
        return None
    except Exception:
        pool.record_timeout(ip)
        return None


def resolve_ns(domain: str, pool: ResolverPool) -> List[str]:
    r, ip = pool.get()
    start = time.time()
    try:
        answers = r.resolve(domain, "NS")
        pool.record_success(ip, (time.time() - start) * 1000)
        ns_ips = []
        for rdata in answers:
            try:
                ns_ips.append(socket.gethostbyname(str(rdata.target)))
            except Exception:
                pass
        return ns_ips
    except Exception:
        pool.record_timeout(ip)
        return []


def resolve_txt(fqdn: str, pool: ResolverPool) -> Optional[List[str]]:
    r, ip = pool.get()
    start = time.time()
    try:
        answers = r.resolve(fqdn, "TXT")
        pool.record_success(ip, (time.time() - start) * 1000)
        return [" ".join(a.strings) for a in answers]
    except dns.exception.FormError:
        pool.record_servfail(ip)
        return None
    except dns.resolver.NoAnswer:
        pool.record_result(ip, (time.time() - start) * 1000, "noanswer")
        return None
    except Exception:
        pool.record_timeout(ip)
        return None


def resolve_cname(fqdn: str, pool: ResolverPool) -> Optional[str]:
    r, ip = pool.get()
    start = time.time()
    try:
        answers = r.resolve(fqdn, "CNAME")
        pool.record_success(ip, (time.time() - start) * 1000)
        return str(answers[0].target).rstrip(".")
    except dns.exception.FormError:
        pool.record_servfail(ip)
        return None
    except dns.resolver.NoAnswer:
        pool.record_result(ip, (time.time() - start) * 1000, "noanswer")
        return None
    except Exception:
        pool.record_timeout(ip)
        return None


def resolve_any(fqdn: str, pool: ResolverPool) -> Optional[List[str]]:
    r, ip = pool.get()
    start = time.time()
    try:
        answers = r.resolve(fqdn, "ANY")
        pool.record_success(ip, (time.time() - start) * 1000)
        return [str(a) for a in answers]
    except dns.exception.FormError:
        pool.record_servfail(ip)
        return None
    except Exception:
        pool.record_timeout(ip)
        return None

# ─── Wildcard Detector ───────────────────────────────────────────────────────

class WildcardDetector:
    def __init__(self, domain: str, pool: ResolverPool):
        self.domain = domain
        self.pool = pool
        self.wildcard_ips: Set[str] = set()
        self.active = False
        self._lock = __import__("threading").Lock()

    def detect(self) -> bool:
        console.print("\n[bold yellow][*][/bold yellow] Wildcard Detection")
        junk = [
            f"{''.join(random.choices(string.ascii_lowercase, k=14))}.{self.domain}",
            f"{''.join(random.choices(string.ascii_lowercase, k=10))}.{self.domain}",
            f"{''.join(random.choices(string.ascii_lowercase, k=8))}.{self.domain}",
        ]
        for name in junk:
            ips = resolve_a(name, self.pool)
            if ips:
                with self._lock:
                    self.wildcard_ips.update(ips)
                with self._lock:
                    self.active = True

        if self.active:
            console.print(
                f"  [bold yellow][!][/bold yellow] Wildcard detected "
                f"→ [red]{', '.join(self.wildcard_ips)}[/red]  (will filter)"
            )
        else:
            console.print("  [dim]No wildcard detected — clean DNS ✓[/dim]")
        return self.active

    def is_wildcard(self, ips: List[str]) -> bool:
        """Return True if ALL IPs overlap with wildcard IPs.

        If a subdomain shares even one IP with a wildcard but also has
        a non-wildcard IP, we keep it (it may be load-balanced across
        the wildcard infrastructure). If ALL IPs are in the wildcard
        set, it is almost certainly a wildcard artifact.
        """
        if not self.active or not ips:
            return False
        # Bug fix: use intersection. If ANY IP overlaps with wildcard IPs,
        # check if ALL IPs are in the wildcard set (true wildcard artifact).
        # Original bug: set(ips).issubset(...) requires ALL IPs to be in the set,
        # but a real subdomain that happens to share ONE IP with a wildcard
        # would incorrectly bypass the filter if it has other non-wildcard IPs.
        # The correct fix: if all IPs are a subset of wildcard IPs → wildcard.
        # But also: if ANY IP is shared with wildcard, we need to be conservative.
        # Best approach: check intersection size > 0 AND all IPs are subset.
        # However, a legitimate subdomain that resolves to BOTH a wildcard IP
        # AND its own IP should not be filtered. The issubset check handles this.
        # The real bug was: wildcard_ips is a set of strings but we're comparing
        # with set(ips) which is also strings. This IS correct.
        # The bug is that issubset returns False when the subdomain has mixed IPs.
        # For a real subdomain: if it has multiple IPs and only some match,
        # issubset returns False → not filtered → correct.
        # The issue is that wildcard_ips is a flat set, not per-name.
        # This is a known limitation of the approach. Keep the logic but
        # ensure thread-safety with the lock we added above.
        wildcard_overlap = set(ips) & self.wildcard_ips
        if not wildcard_overlap:
            return False  # No overlap → definitely not a wildcard
        # Some overlap — check if ALL IPs are in the wildcard set
        return set(ips).issubset(self.wildcard_ips)

# ─── Module 01: DNS Brute Force ──────────────────────────────────────────────

class BruteForcer:
    def __init__(self, cfg: Config, pool: ResolverPool,
                 wc: WildcardDetector, results: ResultCollector,
                 rate_monitor=None, checkpoint_manager=None):
        self.cfg = cfg
        self.pool = pool
        self.wc = wc
        self.results = results
        self.rate_monitor = rate_monitor
        self.checkpoint = checkpoint_manager
        self._backoff_logged = False

    def _try(self, word: str) -> Optional[Tuple[str, List[str]]]:
        # Optional jitter — stagger queries slightly to avoid burst patterns
        if self.cfg.jitter > 0:
            time.sleep(random.random() * self.cfg.jitter / 1000.0)

        fqdn = f"{word}.{self.cfg.domain}"
        ips = resolve_a(fqdn, self.pool)
        if ips and not self.wc.is_wildcard(ips):
            return fqdn, ips
        if ips is None:
            # Try CNAME fallback
            try:
                r, r_ip = self.pool.get()
                start = time.time()
                ans = r.resolve(fqdn, "CNAME")
                self.pool.record_success(r_ip, (time.time() - start) * 1000)
                cnames = [str(x.target).rstrip(".") for x in ans]
                if cnames:
                    return fqdn, cnames
            except Exception:
                pass
        return None

    def run(self, wordlist: List[str], label: str = "01") -> Set[str]:
        # Shuffle wordlist to distribute query patterns across resolvers
        if self.cfg.shuffle:
            random.shuffle(wordlist)

        console.print(
            f"\n[bold blue][{label}][/bold blue] DNS Brute Force — "
            f"[cyan]{len(wordlist):,}[/cyan] words"
            + (f" [dim](shuffled)[/dim]" if self.cfg.shuffle else "")
        )
        found: Set[str] = set()
        words_total = len(wordlist)
        words_done = 0
        threads_current = [self.cfg.threads]  # mutable for backoff adjustment

        # Batching: submit in waves to avoid OOM with large wordlists.
        # Max pending futures = threads * 10 (10 batches of work ahead).
        BATCH_SIZE = self.cfg.threads * 10
        batch = []
        pending = {}

        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TaskProgressColumn(), console=console, transient=True,
        ) as prog:
            task = prog.add_task("[cyan]Resolving...", total=words_total)
            ex = ThreadPoolExecutor(max_workers=threads_current[0])
            it = iter(wordlist)

            while words_done < words_total:
                # Fill batch while under limit
                while len(pending) < BATCH_SIZE:
                    try:
                        w = next(it)
                    except StopIteration:
                        break
                    fut = ex.submit(self._try, w)
                    pending[fut] = w

                # Wait for at least one to finish
                if not pending:
                    break
                done, _ = wait(
                    pending, return_when=FIRST_COMPLETED
                )
                for fut in done:
                    word = pending.pop(fut)
                    prog.advance(task)
                    words_done += 1
                    try:
                        r = fut.result()
                    except Exception:
                        r = None

                    # Rate limit monitoring
                    if self.rate_monitor and self.pool and self.pool._last_ip:
                        ip = self.pool._last_ip
                        if r:
                            self.rate_monitor.record_success(ip, 0.0)
                        elif self.pool._last_result_type not in ("success", "nxdomain", "noanswer"):
                            self.rate_monitor.record_failure(ip, self.pool._last_result_type.upper())

                        if self.rate_monitor.should_backoff() and not self._backoff_logged:
                            msg = self.rate_monitor.apply_backoff(console, threads_current)
                            if msg:
                                console.print(f"\n  {msg}")
                                self._backoff_logged = True

                    if r:
                        fqdn, ips = r
                        self.results.add_sync(fqdn, ips, f"brute[{label}]")
                        found.add(fqdn)

            ex.shutdown(wait=False)

        console.print(f"  [dim]→ {len(found)} found[/dim]")
        if self.pool:
            console.print(f"  [dim]→ {self.pool.health_summary()}[/dim]")
        return found

# ─── Module 02: Permutation Engine ──────────────────────────────────────────

class PermutationEngine:
    def generate(self, known: Set[str], domain: str) -> Set[str]:
        mutations: Set[str] = set()
        for sub in known:
            part = sub.replace(f".{domain}", "")
            if not part or part == domain:
                continue
            for pfx in PERMUTATION_PREFIXES:
                for sep in PERMUTATION_SEPARATORS:
                    mutations.add(f"{pfx}{sep}{part}")
                    mutations.add(f"{part}{sep}{pfx}")
            # Increment/decrement numbers
            for num in re.findall(r'\d+', part):
                for delta in [-1, 1, 2]:
                    new = str(int(num) + delta)
                    if int(new) >= 0:
                        mutations.add(part.replace(num, new, 1))
        # Strip already known
        return {m for m in mutations if f"{m}.{domain}" not in known}

    def run(self, known: Set[str], cfg: Config, pool: ResolverPool,
            wc: WildcardDetector, results: ResultCollector) -> Set[str]:
        mutations = self.generate(known, cfg.domain)
        console.print(
            f"\n[bold blue][02][/bold blue] Permutation Engine — "
            f"[cyan]{len(mutations):,}[/cyan] mutations from {len(known)} seeds"
        )
        if not mutations:
            console.print("  [dim]→ No mutations generated (no seeds yet)[/dim]")
            return set()
        bf = BruteForcer(cfg, pool, wc, results)
        return bf.run(list(mutations), label="02")

# ─── Module 03: Zone Transfer ────────────────────────────────────────────────

class ZoneTransfer:
    def __init__(self, cfg: Config, pool: ResolverPool, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.results = results

    def run(self) -> Set[str]:
        console.print(f"\n[bold blue][03][/bold blue] Zone Transfer (AXFR/IXFR)")
        found: Set[str] = set()
        ns_ips = resolve_ns(self.cfg.domain, self.pool)
        if not ns_ips:
            console.print("  [dim]→ Could not resolve nameservers[/dim]")
            return found
        console.print(f"  [dim]→ Trying {len(ns_ips)} nameservers...[/dim]")
        for ns_ip in ns_ips:
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, self.cfg.domain, timeout=10)
                )
                for name in zone.nodes:
                    s = str(name).rstrip(".")
                    if s in ("@", ""):
                        continue
                    fqdn = f"{s}.{self.cfg.domain}"
                    ips = resolve_a(fqdn, self.pool) or ["[zone-record]"]
                    self.results.add_sync(fqdn, ips, "zonetransfer")
                    found.add(fqdn)
                console.print(
                    f"  [bold green]✓ ZONE TRANSFER SUCCESS on {ns_ip}![/bold green] "
                    f"Got {len(found)} records."
                )
                break
            except dns.exception.FormError:
                console.print(f"  [dim]→ {ns_ip}: refused[/dim]")
            except Exception as e:
                console.print(f"  [dim]→ {ns_ip}: {str(e)[:60]}[/dim]")
        if not found:
            console.print("  [dim]→ All NS refused zone transfer (expected in modern configs)[/dim]")
        return found

# ─── Module 04: DNSSEC NSEC Walking ─────────────────────────────────────────

class NSECWalker:
    def __init__(self, cfg: Config, pool: ResolverPool, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.results = results

    def _nsec(self, name: str, ns: str) -> Optional[Tuple[str, str]]:
        try:
            req = dns.message.make_query(name, dns.rdatatype.A, want_dnssec=True)
            req.flags |= dns.flags.CD
            resp = dns.query.udp(req, ns, timeout=5)
            for rrset in resp.authority:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    for rdata in rrset:
                        cur = str(rrset.name).rstrip(".")
                        nxt = str(rdata.next).rstrip(".")
                        return cur, nxt
        except Exception:
            pass
        return None

    def run(self) -> Set[str]:
        console.print(f"\n[bold blue][04][/bold blue] DNSSEC NSEC/NSEC3 Walking")
        found: Set[str] = set()
        ns_ips = resolve_ns(self.cfg.domain, self.pool)
        if not ns_ips:
            console.print("  [dim]→ No NS resolved[/dim]")
            return found
        ns = ns_ips[0]
        current = self.cfg.domain
        visited: Set[str] = set()
        max_steps = 1000

        for _ in range(max_steps):
            if current in visited:
                break
            visited.add(current)
            pair = self._nsec(current, ns)
            if not pair:
                break
            _, nxt = pair
            if nxt.endswith(f".{self.cfg.domain}"):
                ips = resolve_a(nxt, self.pool) or ["[nsec-only]"]
                self.results.add_sync(nxt, ips, "nsec-walk")
                found.add(nxt)
            # BUG FIX: nxt <= current as string comparison is unreliable for DNS names.
            # Use proper DNS name comparison: convert to dns.name.Name objects.
            # A DNS name is "greater" if it comes later in alphabetical order (a < z).
            # The wrap-around is detected when nxt equals domain (back to start).
            # Also check: when nxt has fewer labels than current, we've likely wrapped.
            try:
                nxt_name = dns.name.from_text(nxt)
                cur_name = dns.name.from_text(current)
                wrapped = nxt == self.cfg.domain
                # Lexicographic comparison using dns.name — proper DNS ordering
                lexicographic_wrap = nxt_name < cur_name
                # Also check: if nxt has fewer labels and is alphabetically before,
                # likely wrapped (e.g. z.example.com -> a.example.com)
                fewer_labels = len(nxt_name.labels) < len(cur_name.labels)
                if wrapped or (lexicographic_wrap and fewer_labels):
                    break
            except Exception:
                # Fallback: if DNS comparison fails, use domain equality check
                if nxt == self.cfg.domain:
                    break
            current = nxt

        if found:
            console.print(f"  [bold green]✓ NSEC walk found {len(found)} names![/bold green]")
        else:
            console.print("  [dim]→ NSEC3 (hashed) or no DNSSEC — walk not possible[/dim]")
        return found

# ─── Module 05: DNS Cache Snooping ──────────────────────────────────────────

class CacheSnooper:
    def __init__(self, cfg: Config, results: ResultCollector):
        self.cfg = cfg
        self.results = results

    def _snoop(self, fqdn: str, ns_ip: str) -> Optional[List[str]]:
        """Non-recursive query: if answer exists, it was cached → subdomain in use."""
        try:
            req = dns.message.make_query(fqdn, dns.rdatatype.A)
            req.flags &= ~dns.flags.RD  # Clear RD bit
            resp = dns.query.udp(req, ns_ip, timeout=3)
            if resp.answer:
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        return [str(r.address) for r in rrset]
        except Exception:
            pass
        return None

    def run(self, known: Set[str], extra_resolvers: Optional[List[str]] = None) -> Set[str]:
        console.print(f"\n[bold blue][05][/bold blue] DNS Cache Snooping")
        found: Set[str] = set()
        probes_ns = extra_resolvers or ["8.8.8.8", "1.1.1.1", "208.67.222.222"]

        # Build probe list: known + common guesses
        targets = list(known) if known else []
        for word in ["www", "mail", "admin", "vpn", "internal", "api",
                     "dev", "staging", "intranet", "corp"]:
            targets.append(f"{word}.{self.cfg.domain}")
        targets = list(set(targets))

        hits = 0
        for ns_ip in probes_ns:
            for fqdn in targets:
                ips = self._snoop(fqdn, ns_ip)
                if ips:
                    self.results.add_sync(fqdn, ips, f"cache-snoop@{ns_ip}")
                    found.add(fqdn)
                    hits += 1

        console.print(f"  [dim]→ {hits} cached entries across {len(probes_ns)} resolvers[/dim]")
        return found

# ─── Module 06: IPv6 AAAA Enumeration ───────────────────────────────────────

class IPv6Enumerator:
    def __init__(self, cfg: Config, pool: ResolverPool,
                 wc: WildcardDetector, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.wc = wc
        self.results = results

    def _try(self, word: str) -> Optional[Tuple[str, List[str]]]:
        fqdn = f"{word}.{self.cfg.domain}"
        ips = resolve_aaaa(fqdn, self.pool)
        if ips:
            return fqdn, [f"[IPv6] {ip}" for ip in ips]
        return None

    def run(self, wordlist: List[str]) -> Set[str]:
        console.print(
            f"\n[bold blue][06][/bold blue] IPv6 AAAA Enumeration — "
            f"[cyan]{len(wordlist):,}[/cyan] words"
        )
        found: Set[str] = set()
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TaskProgressColumn(), console=console, transient=True,
        ) as prog:
            task = prog.add_task("[cyan]IPv6 probing...", total=len(wordlist))
            with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
                fs = {ex.submit(self._try, w): w for w in wordlist}
                for f in as_completed(fs):
                    prog.advance(task)
                    r = f.result()
                    if r:
                        fqdn, ips = r
                        self.results.add_sync(fqdn, ips, "ipv6-aaaa")
                        found.add(fqdn)
        console.print(f"  [dim]→ {len(found)} IPv6-only subdomains[/dim]")
        return found

# ─── Module 07: TLS SNI Probing ─────────────────────────────────────────────

class TLSSNIProber:
    def __init__(self, cfg: Config, results: ResultCollector):
        self.cfg = cfg
        self.results = results

    def _probe(self, ip: str, hostname: str, port: int = 443) -> bool:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                    cert = tls.getpeercert()
                    if not cert:
                        return False
                    san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    cn_list = [v for ent in cert.get("subject", [])
                               for k, v in [ent] if k == "commonName"]
                    all_names = san + cn_list
                    return any(self.cfg.domain in n for n in all_names)
        except Exception:
            return False

    def _expand_range(self, ip_range: str) -> List[str]:
        import ipaddress
        try:
            net = ipaddress.ip_network(ip_range, strict=False)
            return [str(h) for h in list(net.hosts())[:512]]
        except Exception:
            return [ip_range]

    def run(self, wordlist: List[str]) -> Set[str]:
        console.print(f"\n[bold blue][07][/bold blue] TLS SNI Probing")
        found: Set[str] = set()
        if not self.cfg.ip_ranges:
            console.print("  [dim]→ No --ip-ranges provided. Skipping.[/dim]")
            return found

        all_ips: List[str] = []
        for r in self.cfg.ip_ranges:
            all_ips.extend(self._expand_range(r))

        hostnames = [f"{w}.{self.cfg.domain}" for w in wordlist[:300]]
        console.print(f"  [dim]→ {len(all_ips)} IPs × {len(hostnames)} hostnames[/dim]")

        def scan_ip(ip: str) -> List[Tuple[str, str]]:
            hits = []
            for h in hostnames:
                if self._probe(ip, h):
                    hits.append((h, ip))
            return hits

        with ThreadPoolExecutor(max_workers=50) as ex:
            fs = {ex.submit(scan_ip, ip): ip for ip in all_ips}
            for f in as_completed(fs):
                for hostname, ip in f.result():
                    self.results.add_sync(hostname, [ip], "tls-sni")
                    found.add(hostname)

        console.print(f"  [dim]→ {len(found)} SNI-confirmed subdomains[/dim]")
        return found

# ─── Module 08: CAA Record Pivoting ─────────────────────────────────────────

class CAAPivot:
    def __init__(self, cfg: Config, pool: ResolverPool, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.results = results

    def _probe(self, word: str) -> Optional[Tuple[str, List[str], bool]]:
        """Probe CAA record for a subdomain.

        Returns: (fqdn, data, is_caa_record) or None
        is_caa_record=True means CAA record was found.
        is_caa_record=False means NoAnswer confirmed existence via A record.
        BUG FIX: previously, NoAnswer path returned result but it was never
        added to results. Now we explicitly tag it as 'confirmed via NoAnswer'.
        """
        fqdn = f"{word}.{self.cfg.domain}"
        try:
            r, r_ip = self.pool.get()
            start = time.time()
            ans = r.resolve(fqdn, "CAA")
            self.pool.record_success(r_ip, (time.time() - start) * 1000)
            recs = [f"{rec.flags} {rec.tag.decode()} {rec.value.decode()}" for rec in ans]
            return fqdn, recs, True  # is_caa_record=True
        except dns.resolver.NoAnswer:
            # Domain EXISTS in DNS (not NXDOMAIN) but has no CAA record.
            # This CONFIRMS the subdomain exists. Check A record too.
            ips = resolve_a(fqdn, self.pool)
            if ips:
                # Mark as confirmed by NoAnswer path
                return fqdn, ips, False  # is_caa_record=False
        except dns.resolver.NXDOMAIN:
            pass
        except Exception:
            pass
        return None

    def run(self, wordlist: List[str]) -> Set[str]:
        console.print(
            f"\n[bold blue][08][/bold blue] CAA Record Pivoting — "
            f"[cyan]{len(wordlist):,}[/cyan] words"
        )
        found: Set[str] = set()
        with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
            fs = {ex.submit(self._probe, w): w for w in wordlist}
            for f in as_completed(fs):
                r = f.result()
                if r:
                    fqdn, recs, is_caa = r
                    # BUG FIX: previously NoAnswer path returned result but
                    # was never added. Now both paths are handled correctly.
                    tag = "caa-record" if is_caa else "caa-confirmed"
                    self.results.add_sync(fqdn, recs, tag)
                    found.add(fqdn)
        console.print(f"  [dim]→ {len(found)} confirmed via CAA[/dim]")
        return found

# ─── Module 09: CORS Origin Reflection ──────────────────────────────────────

class CORSMiner:
    def __init__(self, cfg: Config, pool: ResolverPool, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.results = results

    async def _probe(self, session: aiohttp.ClientSession,
                     endpoint: str, hostname: str) -> Optional[str]:
        origin = f"https://{hostname}"
        try:
            async with session.get(
                endpoint,
                headers={"Origin": origin, "User-Agent": "ActiveSubEnum/1.0"},
                timeout=aiohttp.ClientTimeout(total=5),
                ssl=False,
                allow_redirects=False,
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == origin:
                    return hostname
        except Exception:
            pass
        return None

    async def _run_async(self, endpoints: List[str], hostnames: List[str]) -> Set[str]:
        found: Set[str] = set()
        conn = aiohttp.TCPConnector(limit=80, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as sess:
            tasks = [
                self._probe(sess, ep, h)
                for ep in endpoints
                for h in hostnames
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and isinstance(r, str):
                    ips = resolve_a(r, ResolverPool(self.cfg.resolvers)) or ["[cors-only]"]
                    await self.results.add(r, ips, "cors-reflection")
                    found.add(r)
        return found

    def run(self, known: Set[str], wordlist: List[str]) -> Set[str]:
        console.print(f"\n[bold blue][09][/bold blue] CORS Origin Reflection Mining")
        endpoints = []
        for sub in list(known)[:8]:
            endpoints += [f"https://{sub}/", f"https://{sub}/api/v1/"]
        if self.cfg.api_endpoint:
            endpoints.append(self.cfg.api_endpoint)
        if not endpoints:
            endpoints = [
                f"https://www.{self.cfg.domain}/",
                f"https://api.{self.cfg.domain}/",
            ]
        hostnames = [f"{w}.{self.cfg.domain}" for w in wordlist[:150]]
        console.print(f"  [dim]→ {len(endpoints)} endpoints × {len(hostnames)} origins[/dim]")
        found = asyncio.run(self._run_async(endpoints, hostnames))
        console.print(f"  [dim]→ {len(found)} CORS-trusted origins[/dim]")
        return found

# ─── Module 10: DNS CHAOS Class ──────────────────────────────────────────────

class CHAOSQuery:
    def __init__(self, cfg: Config, pool: ResolverPool, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.results = results

    def _query(self, qname: str, ns_ip: str) -> Optional[str]:
        try:
            req = dns.message.make_query(
                qname, dns.rdatatype.TXT, rdclass=dns.rdataclass.CHAOS
            )
            resp = dns.query.udp(req, ns_ip, timeout=5)
            for rrset in resp.answer:
                for rdata in rrset:
                    if hasattr(rdata, "strings"):
                        return b"".join(rdata.strings).decode("utf-8", errors="ignore")
        except Exception:
            pass
        return None

    def run(self) -> Set[str]:
        console.print(f"\n[bold blue][10][/bold blue] DNS CHAOS Class Queries")
        found: Set[str] = set()
        ns_ips = resolve_ns(self.cfg.domain, self.pool)
        if not ns_ips:
            console.print("  [dim]→ No NS resolved[/dim]")
            return found

        hits = []
        for ns_ip in ns_ips:
            for qname in CHAOS_QUERIES:
                val = self._query(qname, ns_ip)
                if val:
                    hits.append(f"{qname}@{ns_ip}: {val}")
                    console.print(
                        f"  [bold magenta][chaos][/bold magenta] "
                        f"{qname} → [yellow]{val}[/yellow]"
                    )
                    # Extract any hostnames from value
                    pattern = rf'[a-zA-Z0-9._-]+\.{re.escape(self.cfg.domain)}'
                    for h in re.findall(pattern, val):
                        ips = resolve_a(h, self.pool) or ["[chaos-leak]"]
                        self.results.add_sync(h, ips, "chaos-class")
                        found.add(h)

        if not hits:
            console.print("  [dim]→ No CHAOS responses (well-configured servers)[/dim]")
        return found

# ─── Module 11: VHost Fuzzing ────────────────────────────────────────────────

class VHostFuzzer:
    def __init__(self, cfg: Config, pool: ResolverPool, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.results = results

    async def _baseline(self, sess: aiohttp.ClientSession,
                        url: str) -> Tuple[int, int]:
        junk = f"nonexistent-{random.randint(10000,99999)}.{self.cfg.domain}"
        try:
            async with sess.get(
                url, headers={"Host": junk},
                timeout=aiohttp.ClientTimeout(total=5), ssl=False,
                allow_redirects=False,
            ) as r:
                body = await r.read()
                return r.status, len(body)
        except Exception:
            return 0, 0

    async def _probe(self, sess: aiohttp.ClientSession, url: str,
                     hostname: str, b_status: int, b_len: int) -> Optional[str]:
        try:
            async with sess.get(
                url,
                headers={"Host": hostname, "User-Agent": "ActiveSubEnum/1.0"},
                timeout=aiohttp.ClientTimeout(total=5), ssl=False,
                allow_redirects=False,
            ) as r:
                body = await r.read()
                diff_len = abs(len(body) - b_len)
                if diff_len > 200 or r.status != b_status:
                    if r.status not in (400,):
                        return hostname
        except Exception:
            pass
        return None

    async def _fuzz_ip(self, ip: str, port: int,
                       words: List[str]) -> Set[str]:
        found: Set[str] = set()
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{ip}:{port}/"
        conn = aiohttp.TCPConnector(limit=60, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as sess:
            b_status, b_len = await self._baseline(sess, url)
            if b_status == 0:
                return found
            tasks = [
                self._probe(sess, url, f"{w}.{self.cfg.domain}", b_status, b_len)
                for w in words
            ]
            batch = 60
            for i in range(0, len(tasks), batch):
                results = await asyncio.gather(*tasks[i:i+batch], return_exceptions=True)
                for r in results:
                    if r and isinstance(r, str):
                        tag = f"vhost@{ip}:{port}"
                        self.results.add_sync(r, [f"[{tag}]"], "vhost-fuzz")
                        found.add(r)
        return found

    def run(self, known: Set[str], wordlist: List[str]) -> Set[str]:
        console.print(f"\n[bold blue][11][/bold blue] VHost Fuzzing")
        target_ips: Set[str] = set()
        for sub in list(known)[:5]:
            ips = resolve_a(sub, self.pool)
            if ips:
                target_ips.update(ips)
        main_ips = resolve_a(self.cfg.domain, self.pool)
        if main_ips:
            target_ips.update(main_ips)
        if not target_ips:
            console.print("  [dim]→ No target IPs for vhost fuzzing[/dim]")
            return set()
        console.print(
            f"  [dim]→ {len(target_ips)} IPs × {len(self.cfg.ports)} ports × "
            f"{min(len(wordlist), self.cfg.vhost_max_words)} words[/dim]"
        )
        found: Set[str] = set()
        words = wordlist[:self.cfg.vhost_max_words]
        for ip in list(target_ips)[:self.cfg.vhost_max_ips]:
            for port in self.cfg.ports:
                new = asyncio.run(self._fuzz_ip(ip, port, words))
                found.update(new)
        console.print(f"  [dim]→ {len(found)} vhosts discovered[/dim]")
        return found

# ─── Module 12: Recursive Enumeration ───────────────────────────────────────

class RecursiveEnumerator:
    def __init__(self, cfg: Config, pool: ResolverPool,
                 wc: WildcardDetector, results: ResultCollector):
        self.cfg = cfg
        self.pool = pool
        self.wc = wc
        self.results = results

    def run(self, known: Set[str], depth: int = 2) -> Set[str]:
        console.print(
            f"\n[bold blue][12][/bold blue] Recursive Enumeration "
            f"(depth={depth}, {len(known)} seeds)"
        )
        all_new: Set[str] = set()
        seeds = set(known)

        for level in range(1, depth + 1):
            if not seeds:
                break
            console.print(f"  [dim]→ Level {level}: {len(seeds)} seeds[/dim]")
            new: Set[str] = set()

            def resolve_under(args: Tuple[str, str]) -> Optional[Tuple[str, List[str]]]:
                word, seed_fqdn = args
                fqdn = f"{word}.{seed_fqdn}"
                ips = resolve_a(fqdn, self.pool)
                if ips and not self.wc.is_wildcard(ips):
                    return fqdn, ips
                return None

            pairs = [(w, s) for s in seeds for w in RECURSIVE_SEEDS]
            with ThreadPoolExecutor(max_workers=self.cfg.threads) as ex:
                fs = {ex.submit(resolve_under, p): p for p in pairs}
                for f in as_completed(fs):
                    r = f.result()
                    if r:
                        fqdn, ips = r
                        if fqdn not in all_new:
                            self.results.add_sync(fqdn, ips, f"recursive-l{level}")
                            new.add(fqdn)
                            all_new.add(fqdn)

            seeds = new

        console.print(f"  [dim]→ {len(all_new)} sub-subdomains found recursively[/dim]")
        return all_new

# ─── Output ──────────────────────────────────────────────────────────────────

def save_results(results: ResultCollector, path: str):
    if not path:
        return
    if path.endswith(".json"):
        with open(path, "w") as f:
            json.dump({"total": len(results.found), "subdomains": results.found}, f, indent=2)
    else:
        with open(path, "w") as f:
            for sub in sorted(results.found):
                f.write(sub + "\n")
    console.print(f"\n[bold green][✓] Saved {len(results.found)} results → {path}[/bold green]")


def print_summary(results: ResultCollector, start: float):
    elapsed = time.time() - start
    table = Table(
        title="\n[bold]Active Subdomain Enumeration — Results[/bold]",
        show_header=True, header_style="bold magenta",
        show_lines=False,
    )
    table.add_column("Subdomain", style="cyan", no_wrap=True)
    table.add_column("IP(s) / Record(s)", style="yellow")
    table.add_column("Technique(s)", style="green")
    for sub in sorted(results.found):
        info = results.found[sub]
        table.add_row(sub, ", ".join(info["ips"][:2]), ", ".join(info["techniques"]))
    console.print(table)
    console.print(
        f"\n  [bold]Total:[/bold] [bold green]{len(results.found)}[/bold green] unique subdomains  "
        f"[bold]Time:[/bold] {elapsed:.1f}s\n"
    )

# ─── Wordlist & Resolvers ────────────────────────────────────────────────────

def load_wordlist(path: str) -> List[str]:
    if not path:
        console.print("  [dim]No wordlist — using built-in ({} words)[/dim]".format(len(BUILTIN_WORDLIST)))
        return BUILTIN_WORDLIST

    if not Path(path).exists():
        # Auto-download jhaddix-all.txt from GitHub Gist if not found
        console.print(f"  [yellow][!] Wordlist not found: {path}[/yellow]")
        downloaded_path = _auto_download_wordlist(path)
        if downloaded_path and Path(downloaded_path).exists():
            path = downloaded_path
            console.print(f"  [green][+] Downloaded wordlist: {path}[/green]")
        else:
            console.print(f"  [yellow]    Falling back to built-in wordlist[/yellow]")
            return BUILTIN_WORDLIST

    with open(path, errors="ignore") as f:
        words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    console.print(f"  [dim]Wordlist: {path} ({len(words):,} words)[/dim]")
    return words


def _auto_download_wordlist(requested_path: str) -> Optional[str]:
    """Attempt to download jhaddix-all.txt if it's the requested wordlist."""
    import urllib.request

    # Only auto-download for jhaddix-all.txt or paths that look like the default
    basename = Path(requested_path).name
    if "jhaddix" not in basename.lower() and "all.txt" not in basename.lower():
        return None

    dest_dir = Path("wordlists/external")
    dest_path = dest_dir / "jhaddix-all.txt"
    url = "https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt"

    try:
        os.makedirs(dest_dir, exist_ok=True)
        console.print(f"  [*] Downloading jhaddix-all.txt (~2M words)...")
        console.print(f"    Source: {url}")
        urllib.request.urlretrieve(url, str(dest_path))
        return str(dest_path)
    except Exception as e:
        console.print(f"  [red]    Download failed: {e}[/red]")
        return None


def load_resolvers(path: str = "", resolver_file: str = "", refresh: bool = False) -> List[str]:
    """Load resolvers from file, web fetch, or fallback pool.

    Priority: explicit file > resolver_file arg > healthy pool >
    web fetch > DEFAULT_RESOLVERS.
    """
    if path and Path(path).exists():
        with open(path) as f:
            resolvers = [l.strip() for l in f if l.strip()]
        if resolvers:
            return resolvers
    if resolver_file and Path(resolver_file).exists():
        with open(resolver_file) as f:
            resolvers = [l.strip() for l in f if l.strip()]
        if resolvers:
            return resolvers
    # Auto-use pre-validated healthy pool
    healthy = "/tmp/fresh_resolvers/healthy.txt"
    if Path(healthy).exists() and not refresh:
        try:
            with open(healthy) as f:
                resolvers = [l.strip() for l in f if l.strip()]
            if resolvers:
                print(f"  [i] Auto-loading {len(resolvers)} healthy resolvers")
                return resolvers
        except Exception:
            pass
    # Fetch fresh resolvers from web
    from core.resolver import fetch_resolvers_from_web
    print(f"  [*] Fetching resolvers from public sources...")
    raw = fetch_resolvers_from_web(timeout=10)
    if raw:
        print(f"  [i] Fetched {len(raw)} resolvers from web")
        return raw[:5000]  # cap at 5000
    return list(DEFAULT_RESOLVERS)

# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="activesubenum",
        description="Active Subdomain Enumeration — 12 techniques beyond the standard playbook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
TECHNIQUES (use with --techniques, comma-separated or 'all'):
  bruteforce   [01] DNS Brute Force + wildcard filtering
  permutation  [02] Mutation from discovered subdomains
  zonetransfer [03] AXFR/IXFR zone transfer attempts
  nsec         [04] DNSSEC NSEC chain walking
  cachesnoop   [05] DNS cache snooping (non-recursive queries)
  ipv6         [06] AAAA record enumeration (IPv6 blind spot)
  tlssni       [07] TLS SNI probing across IP ranges
  caa          [08] CAA record pivoting to confirm existence
  cors         [09] CORS Origin reflection mining
  chaos        [10] DNS CHAOS class (version/hostname leaks)
  vhost        [11] Virtual host fuzzing via Host header
  recursive    [12] Recursive sub-subdomain discovery

EXAMPLES:
  # Full scan with wordlist
  python3 activesubenum.py -d example.com -w /usr/share/seclists/Discovery/DNS/all.txt

  # Specific techniques only
  python3 activesubenum.py -d example.com -w wordlist.txt --techniques bruteforce,permutation,nsec,chaos

  # With IP ranges for TLS SNI probing
  python3 activesubenum.py -d example.com --ip-ranges 104.21.0.0/24,172.67.0.0/24

  # Save results
  python3 activesubenum.py -d example.com -w wordlist.txt -o results.json
  python3 activesubenum.py -d example.com -w wordlist.txt -o subdomains.txt

  # Dry run — see what would be attempted
  python3 activesubenum.py -d example.com --dry-run

  # Opsec mode — stealthy, minimal noise
  python3 activesubenum.py -d example.com --opsec

  # Resume interrupted scan
  python3 activesubenum.py -d example.com --resume
        """,
    )
    p.add_argument("-d", "--domain", required=False, help="Target domain (e.g. example.com)")
    p.add_argument("-w", "--wordlist", default="", help="Path to wordlist")
    p.add_argument("-r", "--resolvers", default="", help="Path to custom resolver IPs file")
    p.add_argument("-t", "--threads", type=int, default=100, help="Threads (default: 100)")
    p.add_argument("--timeout", type=int, default=3, help="DNS timeout seconds (default: 3)")
    p.add_argument(
        "--techniques", default="all",
        help="Comma-separated techniques or 'all' (default: all)"
    )
    p.add_argument(
        "--ip-ranges", default="",
        help="IP ranges for TLS SNI probing, comma-separated (e.g. 104.21.0.0/24)"
    )
    p.add_argument("--depth", type=int, default=2, help="Recursive depth (default: 2)")
    p.add_argument("--api-endpoint", default="", help="API endpoint for CORS mining")
    p.add_argument("--ports", default="80,443,8080,8443",
                   help="Ports for vhost fuzzing (default: 80,443,8080,8443)")
    p.add_argument("-o", "--output", default="", help="Output file (.txt or .json)")
    p.add_argument("-v", "--verbose", action="store_true")
    # Part 1: dry run
    p.add_argument("--dry-run", dest="dry_run", action="store_true",
                   help="Show what each technique WOULD do without executing")
    # Part 7: output format
    p.add_argument("--format", dest="output_format", default="auto",
                   choices=["auto", "json", "txt", "csv", "md"],
                   help="Output format (default: auto — inferred from -o extension)")
    # Part 7: skip HTTP probe
    p.add_argument("--skip-http-probe", dest="skip_http_probe", action="store_true",
                   help="Skip HTTP probe phase after enumeration")
    # Part 7: rate limit
    p.add_argument("--rate-limit", type=int, default=0,
                   help="Max DNS queries per second per resolver (0=unlimited)")
    # Part 7: sort output
    p.add_argument("--sort", dest="sort_by", default="score",
                   choices=["score", "alpha", "ip", "technique"],
                   help="Sort results by: score (default), alpha, ip, technique")
    # Part 7: opsec mode
    p.add_argument("--opsec", dest="opsec_mode", action="store_true",
                   help="Opsec mode: stealth techniques only, no HTTP noise")
    # Part 8: refresh resolvers
    p.add_argument("--refresh-resolvers", dest="refresh_resolvers", action="store_true",
                   help="Force refresh resolver list from public sources")
    p.add_argument("--resolvers-file", dest="resolvers_file", default="",
                   help="Use specific resolver file (bypasses auto-refresh)")
    # Rate limit & performance
    p.add_argument("--max-rate", dest="max_rate", type=int, default=0,
                   help="Hard cap on DNS queries per second across all threads (0=unlimited)")
    p.add_argument("--jitter", type=int, default=0,
                   help="Add random delay (ms) per query per thread for stealth (default: 0)")
    p.add_argument("--shuffle", dest="shuffle", action="store_true",
                   help="Randomize wordlist order before brute forcing")
    # Part 7: resume
    p.add_argument("--resume", dest="resume", action="store_true",
                   help="Resume interrupted scan from .json state file")
    # Part 7: skip wordlist cleaning
    p.add_argument("--skip-clean", dest="skip_clean", action="store_true",
                   help="Skip wordlist sanitization step")
    # Part 7: permutation wordlist
    p.add_argument("--permutation-wordlist", dest="permutation_wordlist", default="",
                   help="Custom wordlist for permutation engine (separate from -w)")
    # Part 7: annotate
    p.add_argument("--annotate", dest="annotate", action="store_true",
                   help="Interactive note-taking for high-priority subdomains")
    # Part 7: HTTP probe timeout
    p.add_argument("--http-timeout", type=int, default=5,
                   help="HTTP probe timeout seconds (default: 5)")
    # Part 7: vhost limits
    p.add_argument("--vhost-max-words", type=int, default=400,
                   help="Max words for vhost fuzzing (default: 400)")
    p.add_argument("--vhost-max-ips", type=int, default=5,
                   help="Max IPs for vhost fuzzing (default: 5)")
    # Part 10: about
    p.add_argument("--about", action="store_true",
                   help="Print philosophy and technique overview, then exit")
    # Part 12: Validation pipeline
    p.add_argument("--skip-validate", dest="skip_validate", action="store_true",
                   help="Skip post-enumeration validation (default: run validation)")
    p.add_argument("--fast-validate", dest="fast_validate", action="store_true",
                   help="Fast validation: skip full content fingerprint (Stage 4b)")
    p.add_argument("--validate-only", dest="validate_only", action="store_true",
                   help="Skip enumeration, only run validation on existing results")
    p.add_argument("--input", dest="validate_input", default="",
                   help="Input JSON file for --validate-only mode")
    p.add_argument("--validate-output", dest="validate_output", default="",
                   help="Output directory for validation files (default: same as --output dir)")
    return p.parse_args()

# ─── Main ────────────────────────────────────────────────────────────────────

ALL_TECHNIQUES = [
    "bruteforce", "permutation", "zonetransfer", "nsec",
    "cachesnoop", "ipv6", "tlssni", "caa", "cors",
    "chaos", "vhost", "recursive",
]

# ─── Signal handling ──────────────────────────────────────────────────────────
_scan_interrupted = False

def _handle_signal(signum, frame):
    global _scan_interrupted
    if _scan_interrupted:
        console.print("\n[bold red][!!] Force exit requested. Exiting now.[/bold red]")
        sys.exit(1)
    _scan_interrupted = True
    console.print("\n[bold yellow][*] Scan interrupted by user (CTRL+C). Finishing gracefully...[/bold yellow]")
    console.print("  [dim]Partial results will still be saved. Press CTRL+C again to force exit.[/dim]")


# ─── About text ──────────────────────────────────────────────────────────────
ABOUT_TEXT = """[bold cyan]ActiveSubEnum — Philosophy[/bold cyan]

Most tools find the same subdomains because most hunters
use the same tools. The subdomains that lead to critical bugs
are the ones nobody else found — dev environments left exposed,
IPv6-only staging servers, internal vhosts sharing a CDN IP,
services leaking hostnames through DNS CHAOS queries.

[bold white]This tool is built around one principle:[/bold white]
[bold yellow]  find what others miss, prioritize what matters.[/bold yellow]

Active enumeration is not about running the biggest wordlist.
It is about using every protocol layer — DNS, TLS, HTTP, DNSSEC —
to extract information the target never intended to expose.

[bold white]Every technique in this tool was chosen because it finds[/bold white]
[bold white]something that no other technique in the tool finds.[/bold white]
Every technique you add should meet the same bar.

This tool uses community wordlists built by researchers who
spent years doing real recon. Credits: Jason Haddix (@jhaddix),
Assetnote, Daniel Miessler, Trickest, six2dez, n0kovo, and the
broader bug bounty community. Their work makes this tool possible.
"""


def _print_about():
    console.print(BANNER)
    console.print(Panel(ABOUT_TEXT, title="[bold yellow]⚡  About ActiveSubEnum[/bold yellow]", expand=False))
    sys.exit(0)


def _dry_run(techniques: List[str], cfg: Config, wordlist: List[str]):
    """Print what each technique WOULD do without executing."""
    console.print(Panel(
        f"[bold yellow]--dry-run: no techniques will execute[/bold yellow]\n"
        f"[bold]Target:[/bold]     [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]Techniques:[/bold] {', '.join(techniques)}\n"
        f"[bold]Threads:[/bold]    {cfg.threads}\n"
        f"[bold]Wordlist:[/bold]   {len(wordlist):,} words\n"
        f"[bold]Depth:[/bold]       {cfg.depth}",
        title="[bold yellow]⚡  Dry Run[/bold yellow]",
        expand=False,
    ))
    console.print()

    dry_run_map = {
        "bruteforce": (
            f"[01] DNS Brute Force — resolve A/CNAME for {len(wordlist):,} words "
            f"across {cfg.threads} threads using {len(cfg.resolvers)} resolvers.\n"
            f"      Wildcard detection runs first. CNAME fallback on each miss.",
        ),
        "permutation": (
            f"[02] Permutation Engine — generate mutations from known subdomains.\n"
            f"      Uses prefix/suffix separators and number increment patterns.",
        ),
        "zonetransfer": (
            "[03] Zone Transfer — attempt AXFR against all authoritative NS.\n"
            "      High reward if it works. Zero noise if refused. Always try first.",
        ),
        "nsec": (
            "[04] DNSSEC NSEC Walking — follow NSEC chain if target uses NSEC (not NSEC3).\n"
            "      Provably complete enumeration within the signed zone.",
        ),
        "cachesnoop": (
            "[05] DNS Cache Snooping — non-recursive queries to public resolvers.\n"
            "      Detects cached (actively used) subdomains. High stealth.",
        ),
        "ipv6": (
            f"[06] IPv6 AAAA Enumeration — brute force AAAA records for {len(wordlist):,} words.\n"
            "      The 95% blind spot. Everyone skips this. You won't.",
        ),
        "tlssni": (
            f"[07] TLS SNI Probing — TLS ClientHello with SNI for {len(cfg.ip_ranges)} IP ranges.\n"
            "      Finds subdomains with no DNS entry. Requires --ip-ranges.",
        ),
        "caa": (
            f"[08] CAA Record Pivoting — probe CAA for {len(wordlist):,} words.\n"
            "      NoAnswer ≠ NXDOMAIN. Confirms existence without A record.",
        ),
        "cors": (
            f"[09] CORS Origin Reflection — send crafted Origin headers to live endpoints.\n"
            "      Requires HTTP. Uses aiohttp with 80 concurrent connections.",
        ),
        "chaos": (
            "[10] DNS CHAOS Class — query version.bind, hostname.bind, id.server.\n"
            "      Reveals NS software/version. Zero noise.",
        ),
        "vhost": (
            "[11] VHost Fuzzing — Host header fuzzing against known IPs.\n"
            "      Finds virtual hosts invisible to DNS. Requires live HTTP.",
        ),
        "recursive": (
            f"[12] Recursive Enumeration — brute force beneath discovered subs.\n"
            f"      Depth={cfg.depth}, seeds from all found subdomains.",
        ),
    }

    console.print("[bold]Would run:[/bold]")
    for t in techniques:
        desc = dry_run_map.get(t, f"[??] Unknown technique: {t}")
        console.print(f"  {desc}")

    console.print(f"\n[dim]Total techniques to run: {len(techniques)}[/dim]")
    console.print("[dim]Run without --dry-run to execute.[/dim]")
    sys.exit(0)


def main():
    import signal
    console.print(BANNER)
    args = parse_args()

    # Part 12: Handle --validate-only (load existing results and validate)
    if getattr(args, 'validate_only', False):
        input_file = getattr(args, 'validate_input', '') or ''
        if not input_file:
            console.print("[bold red][!] --validate-only requires --input <file>[/bold red]")
            sys.exit(1)
        from core.validator import validate
        try:
            raw = json.loads(open(input_file).read())
            # Format: {"total": N, "subdomains": {sub: ...}} OR {sub: ...}
            if isinstance(raw, dict) and "subdomains" in raw:
                sub_data = raw["subdomains"]
            else:
                sub_data = raw
            # Filter out non-dict entries (e.g. "total": 14675)
            sub_data = {k: v for k, v in sub_data.items() if isinstance(v, dict)}

            output_dir = os.path.dirname(input_file) or "."
            if getattr(args, 'validate_output', ''):
                output_dir = args.validate_output
            fast = getattr(args, 'fast_validate', False)

            domain = args.domain
            if not domain:
                fname = os.path.basename(input_file)
                # results/tube8.com-jhaddix.json → tube8.com
                domain = fname.split(".json")[0].split("-", 1)[-1] or "target"

            validate(sub_data, domain, fast=fast, output_dir=output_dir)
            console.print(f"\n[bold green][+] Validation complete.[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Validation failed: {e}[/bold red]")
            import traceback
            traceback.print_exc()
        sys.exit(0)

    # Handle --about (doesn't need a domain)
    if args.about:
        _print_about()

    # Validate domain is provided for actual scans
    if not args.domain:
        console.print("[bold red][!] --domain (-d) is required[/bold red]")
        console.print("  Run with --about to see philosophy, or --dry-run -d example.com to preview.")
        sys.exit(1)

    # Set up signal handlers for clean CTRL+C
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    techniques = (
        ALL_TECHNIQUES if args.techniques.strip().lower() == "all"
        else [t.strip() for t in args.techniques.split(",")]
    )

    cfg = Config(
        domain=args.domain.lower().strip(),
        wordlist_path=args.wordlist,
        resolvers=load_resolvers(args.resolvers, args.resolvers_file, args.refresh_resolvers),
        threads=args.threads,
        timeout=args.timeout,
        techniques=techniques,
        ip_ranges=[r.strip() for r in args.ip_ranges.split(",") if r.strip()],
        output=args.output,
        depth=args.depth,
        api_endpoint=args.api_endpoint,
        verbose=args.verbose,
        ports=[int(p) for p in args.ports.split(",")],
        dry_run=args.dry_run,
        vhost_max_words=args.vhost_max_words,
        vhost_max_ips=args.vhost_max_ips,
        output_format=args.output_format,
        skip_http_probe=args.skip_http_probe,
        rate_limit=args.rate_limit,
        sort_by=args.sort_by,
        opsec_mode=args.opsec_mode,
        refresh_resolvers=args.refresh_resolvers,
        resume=args.resume,
        skip_clean=args.skip_clean,
        permutation_wordlist=args.permutation_wordlist,
        annotate=args.annotate,
        http_timeout=args.http_timeout,
        max_rate=getattr(args, 'max_rate', 0),
        jitter=getattr(args, 'jitter', 0),
        shuffle=getattr(args, 'shuffle', False),
        resolvers_file=getattr(args, 'resolvers_file', ''),
    )

    # Opsec mode auto-selects stealth techniques and disables noisy ones
    if cfg.opsec_mode:
        console.print(
            "[bold yellow][OPSEC][/bold yellow] Running in stealth mode. "
            "HTTP techniques disabled. DNS-only enumeration active."
        )
        # Disable noisy techniques
        for t in ["cors", "vhost", "tlssni"]:
            if t in techniques:
                techniques.remove(t)
        cfg.threads = min(cfg.threads, 10)
        cfg.rate_limit = 2  # 2 qps max

    console.print(Panel(
        f"[bold]Target:[/bold]     [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]Techniques:[/bold] {', '.join(techniques)}\n"
        f"[bold]Threads:[/bold]    {cfg.threads}  "
        f"[bold]Timeout:[/bold] {cfg.timeout}s  "
        f"[bold]Depth:[/bold] {cfg.depth}\n"
        f"[bold]Resolvers:[/bold]  {len(cfg.resolvers)} loaded  "
        f"[bold]IP Ranges:[/bold] {cfg.ip_ranges or 'none'}",
        title="[bold yellow]⚡  ActiveSubEnum v1.0[/bold yellow]",
        expand=False,
    ))

    # Handle dry run
    if cfg.dry_run:
        wordlist = load_wordlist(cfg.wordlist_path)
        _dry_run(techniques, cfg, wordlist)

    start = time.time()
    results = ResultCollector(cfg.verbose)
    pool = ResolverPool(cfg.resolvers, cfg.timeout)
    wordlist = load_wordlist(cfg.wordlist_path)

    # Always run wildcard detection
    wc = WildcardDetector(cfg.domain, pool)
    wc.detect()

    found: Set[str] = set()

    def run(name: str) -> bool:
        return name in techniques

    techniques = (
        ALL_TECHNIQUES if args.techniques.strip().lower() == "all"
        else [t.strip() for t in args.techniques.split(",")]
    )

    cfg = Config(
        domain=args.domain.lower().strip(),
        wordlist_path=args.wordlist,
        resolvers=load_resolvers(args.resolvers, args.resolvers_file),
        threads=args.threads,
        timeout=args.timeout,
        techniques=techniques,
        ip_ranges=[r.strip() for r in args.ip_ranges.split(",") if r.strip()],
        output=args.output,
        depth=args.depth,
        api_endpoint=args.api_endpoint,
        verbose=args.verbose,
        ports=[int(p) for p in args.ports.split(",")],
        dry_run=False,
        vhost_max_words=args.vhost_max_words,
        vhost_max_ips=args.vhost_max_ips,
        output_format=args.output_format,
        skip_http_probe=args.skip_http_probe,
        rate_limit=args.rate_limit,
        sort_by=args.sort_by,
        opsec_mode=args.opsec_mode,
        refresh_resolvers=args.refresh_resolvers,
        resume=args.resume,
        skip_clean=args.skip_clean,
        permutation_wordlist=args.permutation_wordlist,
        annotate=args.annotate,
        http_timeout=args.http_timeout,
        max_rate=args.max_rate,
        jitter=args.jitter,
        shuffle=args.shuffle,
        resolvers_file=args.resolvers_file,
    )

    console.print(Panel(
        f"[bold]Target:[/bold]     [cyan]{cfg.domain}[/cyan]\n"
        f"[bold]Techniques:[/bold] {', '.join(techniques)}\n"
        f"[bold]Threads:[/bold]    {cfg.threads}  "
        f"[bold]Timeout:[/bold] {cfg.timeout}s  "
        f"[bold]Depth:[/bold] {cfg.depth}\n"
        f"[bold]Resolvers:[/bold]  {len(cfg.resolvers)} loaded  "
        f"[bold]IP Ranges:[/bold] {cfg.ip_ranges or 'none'}",
        title="[bold yellow]⚡  ActiveSubEnum v1.0[/bold yellow]",
        expand=False,
    ))

    start = time.time()
    results = ResultCollector(cfg.verbose)
    pool = ResolverPool(cfg.resolvers, cfg.timeout)
    wordlist = load_wordlist(cfg.wordlist_path)

    # Always run wildcard detection
    wc = WildcardDetector(cfg.domain, pool)
    wc.detect()

    found: Set[str] = set()

    # Rate limit monitor
    rate_monitor = None
    checkpoint_manager = None
    try:
        from core.rate_monitor import RateLimitMonitor
        rate_monitor = RateLimitMonitor()
        rate_monitor.set_pool(pool)
        rate_monitor.start()
    except Exception:
        pass

    try:
        from core.checkpoint import CheckpointManager
        import os
        out_dir = os.path.dirname(cfg.output) or "results"
        checkpoint_manager = CheckpointManager(cfg.domain, checkpoint_dir=out_dir)
        # Check for resume
        state = checkpoint_manager.load()
        if state:
            # Pre-populate results from checkpoint
            prev_found = state.get("found_so_far", {})
            for sub, data in prev_found.items():
                if isinstance(data, dict):
                    results.found[sub] = data
                else:
                    results.found[sub] = {"ips": data if isinstance(data, list) else [],
                                          "techniques": [state.get("technique", "checkpoint")]}
            console.print(
                f"\n  [cyan][*] Resuming from checkpoint: "
                f"{state['words_done']:,}/{state['words_total']:,} words done. "
                f"{len(prev_found)} subdomains already found.[/cyan]"
            )
            found.update(prev_found.keys())
    except Exception:
        pass

    def run(name: str) -> bool:
        return name in techniques or "all" in techniques

    # 01 — Brute Force
    if run("bruteforce"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        bf = BruteForcer(cfg, pool, wc, results, rate_monitor, checkpoint_manager)
        found |= bf.run(wordlist)

    # 02 — Permutation
    if run("permutation"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        pe = PermutationEngine()
        found |= pe.run(found, cfg, pool, wc, results)

    # 03 — Zone Transfer
    if run("zonetransfer"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        zt = ZoneTransfer(cfg, pool, results)
        found |= zt.run()

    # 04 — NSEC Walking
    if run("nsec"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        nw = NSECWalker(cfg, pool, results)
        found |= nw.run()

    # 05 — Cache Snooping
    if run("cachesnoop"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        cs = CacheSnooper(cfg, results)
        found |= cs.run(found)

    # 06 — IPv6 AAAA
    if run("ipv6"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        iv6 = IPv6Enumerator(cfg, pool, wc, results)
        found |= iv6.run(wordlist)

    # 07 — TLS SNI
    if run("tlssni"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        sni = TLSSNIProber(cfg, results)
        found |= sni.run(wordlist)

    # 08 — CAA Pivot
    if run("caa"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        caa = CAAPivot(cfg, pool, results)
        found |= caa.run(wordlist)

    # 09 — CORS
    if run("cors"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        cors = CORSMiner(cfg, pool, results)
        found |= cors.run(found, wordlist)

    # 10 — CHAOS
    if run("chaos"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        chaos = CHAOSQuery(cfg, pool, results)
        found |= chaos.run()

    # 11 — VHost
    if run("vhost"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        vhf = VHostFuzzer(cfg, pool, results)
        found |= vhf.run(found, wordlist)

    # 12 — Recursive
    if run("recursive"):
        if _scan_interrupted:
            _finish(results, start, cfg)
        re_enum = RecursiveEnumerator(cfg, pool, wc, results)
        found |= re_enum.run(found, cfg.depth)

    # All techniques done — final summary and save
    print_summary(results, start)
    save_results(results, cfg.output)

    # Part 12: Post-enumeration validation pipeline
    if not getattr(args, 'skip_validate', False):
        try:
            from core.validator import validate
            output_dir = os.path.dirname(cfg.output) or "."
            if getattr(args, 'validate_output', ''):
                output_dir = args.validate_output
            fast = getattr(args, 'fast_validate', False)
            validate(results.found, cfg.domain, fast=fast, output_dir=output_dir)
        except Exception as e:
            console.print(f"\n[bold yellow][!] Validation pipeline error: {e}[/bold yellow]")
            import traceback
            traceback.print_exc()


def _finish(results: ResultCollector, start: float, cfg: Config):
    """Called on interrupt — save partial results and exit cleanly."""
    console.print(
        f"\n[bold yellow][*] Saving partial results ({len(results.found)} found)...[/bold yellow]"
    )
    print_summary(results, start)
    save_results(results, cfg.output)
    sys.exit(0)


if __name__ == "__main__":
    main()
